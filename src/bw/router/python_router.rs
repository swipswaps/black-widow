use super::super::prelude::*;

use std::net::{SocketAddr, IpAddr};
use std::sync::{Mutex, Arc};
use std::marker::PhantomData;
use std::sync::mpsc::{Receiver, channel, Sender};
use multiqueue::{MPMCSender, mpmc_queue};
use std::thread;
use std::mem;
use std::convert::TryFrom;
use std::time::{Instant, Duration};
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;

use pyo3::prelude::*;
use pyo3::prepare_freethreaded_python;

static mut PYTHON_ROUTER: Option<Arc<Mutex<PythonEnvironment>>> = None;

pub struct PythonEnvironment {
    remote: Option<ServerRemote>,
    bw_module: PyObject,
    imported_module: bool,
    globals: PyObject,
    interface_name: String,
    on_packet_handlers: Vec<PyObject>,
    on_message_handlers: Vec<PyObject>,
    on_boot_handlers: Vec<PyObject>,
    on_client_handlers: Vec<PyObject>,
}

pub struct PythonExec {
    globals: PyObject,
}

impl PythonExec {
    fn run(self, code: &str) -> () {
        let gil = Python::acquire_gil();
        let py = gil.python();

        if let Err(x) = py.run(code, Some(self.globals.extract(py).unwrap()), None) {
            let dict = PyDict::new(py);
            dict.set_item("err", x);
            println!("Failed running python code");
            let write_error_code = r#"
import time
f = open('python_err.log', mode='a')
f.write('Instance: ' + time.strftime("%c") + '\n')
f.write(str(err) + '\n')
f.close()
"#;

            py.run(write_error_code, Some(self.globals.extract(py).unwrap()), Some(dict));
        }
    }
}

impl PythonEnvironment {
    fn new() -> PythonEnvironment {
        prepare_freethreaded_python();
        let gil = Python::acquire_gil();
        let py = gil.python();

        let m = PyModule::import(py, "bw").or_else(|_| PyModule::new(py, "bw")).unwrap();
        let object = py.eval("globals()", None, None).unwrap().to_object(py);
        let globals: &PyDict = object.extract(py).unwrap();

        globals.set_item("bw", m);

        init_module(py, m);

        PythonEnvironment {
            remote: None,
            bw_module: m.to_object(py),
            interface_name: String::new(),
            imported_module: false,
            globals: globals.to_object(py),
            on_packet_handlers: vec![],
            on_message_handlers: vec![],
            on_boot_handlers: vec![],
            on_client_handlers: vec![],
        }
    }

    fn run(&mut self, script: &str) -> PyResult<()> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        py.run(script, None, Some(self.globals.extract(py).unwrap()));

        Ok(())
    }

    fn set_remote(&mut self, remote: ServerRemote) {
        self.remote = Some(remote);
    }

    fn get_exec(&mut self) -> PythonExec {
        let globals = {
            let gil = Python::acquire_gil();
            let py = gil.python();
            self.globals.clone_ref(py)
        };

        PythonExec {
            globals
        }
    }
}

pub fn use_python<T, F: FnOnce() -> T>(with: F) ->T {
    use_router(|_| {
        with()
    })
}

#[derive(Clone)]
pub struct PythonRouter {
    script: String,
}

impl PythonRouter {
    pub fn new(script: String) -> PythonRouter {
        PythonRouter {
            script,
        }
    }
}

fn use_router<T, F: FnOnce(&mut PythonEnvironment) -> T>(with: F) -> T {
    let mut res = None;

    unsafe {
        if PYTHON_ROUTER.is_none() {
            PYTHON_ROUTER = Some(Arc::new(Mutex::new(PythonEnvironment::new())))
        }

        if let &Some(ref arc) = &PYTHON_ROUTER {
            res = Some(use_item!(mut arc, with(&mut arc)));
        }
    }

    return res.unwrap();
}

fn use_remote<T, F: FnOnce(&ServerRemote) -> T>(f: F) -> Option<T> {
    use_router(|r| {
        if let Some(ref remote) = r.remote {
            Some(f(remote))
        } else {
            None
        }
    })
}

fn run_python_in_router(code: &str) -> () {
    let mut exc = use_router(|r| -> PythonExec {
        r.get_exec()
    });

    exc.run(code)
}

impl Router<PythonRouter> for PythonRouter {
    fn start(&mut self) {
        run_python_in_router(r#"
import traceback

def __run_handler(bw, handler, args):
    try:
        handler(*args)
    except Exception as e:
        bw.log("Failed handler: %s, %s: %s" % (handler, type(e).__name__, e));
        bw.log(traceback.format_exc())
"#);
        let file = File::open(&self.script).unwrap();
        let mut buf_reader = BufReader::new(file);
        let mut contents = String::new();
        buf_reader.read_to_string(&mut contents).unwrap();

        run_python_in_router(&contents);
    }

    fn handle_message(&self, message: Message, addr: SocketAddr, id: Bytes) {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let (bw, cbs, glob) = use_router(|r| -> (_, Vec<PyObject>, _) {
            (r.bw_module.clone_ref(py), r.on_message_handlers.iter().map(|c| c.clone_ref(py)).collect(), r.globals.clone_ref(py))
        });

        let bytes = PyBytes::new(py, &message.payload);
        let id = PyBytes::new(py, &id);

        let dict = PyDict::new(py);
        dict.set_item("__bw", &bw);
        dict.set_item("__type", message.message_type as u8);
        dict.set_item("__bytes", &bytes);
        dict.set_item("__ip", format!("{}", addr.ip()));
        dict.set_item("__port", addr.port());
        dict.set_item("__id", &id);

        let globals: &PyDict = glob.extract(py).unwrap();

        for cb in cbs {
            debug_println!("Running an handler!");
            dict.set_item("__handler", &cb);
            py.run(r#"__run_handler(__bw, __handler, (__type, __bytes, __ip, __port, __id))"#, Some(globals), Some(dict));
        }
    }

    fn handle_packet(&self, packet: Bytes) {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let (bw, glob, cbs) = use_router(|r| -> (_, _, Vec<PyObject>) {
            (r.bw_module.clone_ref(py), r.globals.clone_ref(py), r.on_packet_handlers.iter().map(|c| c.clone_ref(py)).collect())
        });

        let bytes = PyBytes::new(py, &packet);

        let dict = PyDict::new(py);
        dict.set_item("__bw", &bw);
        dict.set_item("__bytes", &bytes);

        let globals: &PyDict = glob.extract(py).unwrap();

        for cb in cbs {
            dict.set_item("__handler", &cb);
            py.run(r#"__run_handler(__bw, __handler, (__bytes,))"#, Some(globals), Some(dict));
        }
    }

    fn ready(&mut self, remote: ServerRemote, own_id: Bytes) {
        println!("Running ready handlers");
        let gil = Python::acquire_gil();
        let py = gil.python();
        let (bw, glob, cbs, interface_name) = use_router(|r| -> (_, _, Vec<PyObject>, _) {
            r.set_remote(remote);

            (r.bw_module.clone_ref(py), r.globals.clone_ref(py), r.on_boot_handlers.iter().map(|c| c.clone_ref(py)).collect(), r.interface_name.clone())
        });

        let py_own_id = PyBytes::new(py, &own_id);

        let dict = PyDict::new(py);
        dict.set_item("__bw", &bw);
        dict.set_item("__interface_name", interface_name);
        dict.set_item("__own_id", &py_own_id);

        let globals: &PyDict = glob.extract(py).unwrap();

        for cb in cbs {
            dict.set_item("__handler", &cb);
            py.run(r#"__run_handler(__bw, __handler, (__interface_name, __own_id))"#, Some(globals), Some(dict));
        }
    }

    fn handle_new_client(&self, addr: SocketAddr, id: Bytes) {
        let gil = Python::acquire_gil();
        let py = gil.python();
        let (bw, glob, cbs) = use_router(|r| -> (_, _, Vec<PyObject>) {
            (r.bw_module.clone_ref(py), r.globals.clone_ref(py), r.on_client_handlers.iter().map(|c| c.clone_ref(py)).collect())
        });

        let id = PyBytes::new(py, &id);

        let dict = PyDict::new(py);
        dict.set_item("__bw", &bw);
        dict.set_item("__ip", format!("{}", addr.ip()));
        dict.set_item("__port", addr.port());
        dict.set_item("__id", &id);

        let globals: &PyDict = glob.extract(py).unwrap();

        for cb in cbs {
            dict.set_item("__handler", &cb);
            py.run(r#"__run_handler(__bw, __handler, (__ip, __port, __id))"#, Some(globals), Some(dict));
        }
    }

    fn set_interface_name(&mut self, interface_name: String) {
        use_router(|r| {
            r.interface_name = interface_name;
        })
    }
}

# [pymodinit(bw)]
fn init_module(py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m, "publish_message")]
    fn publish_message(message_type: u8, payload: Vec<u8>) -> PyResult<()> {
        debug_println!("Publishing message");
        let message = Message::new(message_type, Bytes::from(payload));

        use_remote(|r| r.publish_message(message));

        Ok(())
    }

    #[pyfn(m, "send_message_to_address")]
    fn send_message_to_address(message_type: u8, payload: Vec<u8>, ip: String, port: u16) -> PyResult<()> {
        let ip = ip.parse()?;


        let addr = SocketAddr::new(ip, port);
        let message = Message::new(message_type, Bytes::from(payload));

        use_remote(|r| r.send_message_to_addr(message, addr));

        Ok(())
    }

    #[pyfn(m, "send_message_to_client")]
    fn send_message_to_client(message_type: u8, payload: Vec<u8>, public: Vec<u8>) -> PyResult<()> {
        let message = Message::new(message_type, Bytes::from(payload));
        let id = Bytes::from(public);

        use_remote(|r| r.send_message_to_client(message, id));


        Ok(())
    }

    #[pyfn(m, "write_packet")]
    fn write_packet(payload: Vec<u8>) -> PyResult<()> {
        let packet = Bytes::from(payload);
        use_remote(|r| r.write_packet(packet));

        Ok(())
    }

    #[pyfn(m, "log")]
    fn print(data: String) -> PyResult<()> {
        println!("From python: {}", data);

        Ok(())
    }

    #[pyfn(m, "add_message_handler")]
    fn register_on_message(handler: PyObject) -> PyResult<()> {
        use_router(|r| {
            let gil = Python::acquire_gil();
            let py = gil.python();

            r.on_message_handlers.push(handler.clone_ref(py));
        });

        Ok(())
    }

    #[pyfn(m, "get_interface_name")]
    fn get_interface_name() -> PyResult<String> {
        Ok(use_router(|r| r.interface_name.clone()))
    }

    #[pyfn(m, "imported_bw")]
    fn imported_bw() -> PyResult<()> {
        thread::spawn(move || {
            use_router(|r| {
                r.imported_module = true;
            });
        });

        Ok(())
    }

    #[pyfn(m, "add_packet_handler")]
    fn register_on_packet(handler: PyObject) -> PyResult<()> {
        debug_println!("Adding new packet handler");
        use_router(|r| {
            let gil = Python::acquire_gil();
            let py = gil.python();

            r.on_packet_handlers.push(handler.clone_ref(py));
        });


        Ok(())
    }

    #[pyfn(m, "add_boot_handler")]
    fn register_on_boot(handler: PyObject) -> PyResult<()> {
        debug_println!("Adding new boot handler");
        use_router(|r| {
            let gil = Python::acquire_gil();
            let py = gil.python();

            r.on_boot_handlers.push(handler.clone_ref(py));
        });

        Ok(())
    }

    #[pyfn(m, "add_client_handler")]
    fn register_on_client(handler: PyObject) -> PyResult<()> {
        debug_println!("Adding new client handler");
        use_router(|r| {
            let gil = Python::acquire_gil();
            let py = gil.python();

            r.on_client_handlers.push(handler.clone_ref(py));
        });

        Ok(())
    }

    Ok(())
}