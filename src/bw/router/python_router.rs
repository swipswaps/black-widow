use std::net::{SocketAddr, IpAddr};
use std::sync::{Mutex, Arc};
use std::marker::PhantomData;
use std::sync::mpsc::{Receiver, channel, Sender};
use std::thread;
use std::mem;
use std::time::{Instant, Duration};

use super::super::prelude::*;

use pyo3::prelude::*;
use pyo3::prepare_freethreaded_python;

static mut PYTHON_ROUTER: Option<Arc<Mutex<PythonEnvironment>>> = None;

pub struct PythonEnvironment {
    queue: Vec<ServerEvent>,
    event_receiver: Receiver<RouterEvent>,
    event_sender: Sender<RouterEvent>,
    bw_module: PyObject,
    globals: PyObject,
    on_packet_cb: Vec<PyObject>,
    on_message_cb: Vec<PyObject>,
}

impl PythonEnvironment {
    fn queue(&mut self, event: ServerEvent) {
        self.queue.push(event);
    }

    fn has_queue(&self) -> bool {
        self.queue.len() > 0
    }

    fn flush_queue(&mut self) -> Vec<ServerEvent> {
        mem::replace(&mut self.queue, vec![])
    }

    fn new() -> PythonEnvironment {
        let (event_sender, event_receiver) = channel();

        prepare_freethreaded_python();
        let gil = Python::acquire_gil();
        let py = gil.python();
        let m = PyModule::new(py, "bw").unwrap();
        let globals = PyDict::new(py);

        globals.set_item("bw", m);

        init_module(py, m);

        PythonEnvironment {
            queue: vec![],
            event_sender,
            event_receiver,
            bw_module: m.to_object(py),
            globals: globals.to_object(py),
            on_packet_cb: vec![],
            on_message_cb: vec![],
        }
    }

    fn run(&mut self, script: &str) -> PyResult<()> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        py.run(script, None, Some(self.globals.extract(py).unwrap()));

        Ok(())
    }
}

/**
class Router:
    def on_message(self, message):
        pass

    def on_packet(self, packet):
        pass

    def start(self, packet):
        pass

router = Router()
*/

pub struct PythonRouter {
    _priv: PhantomData<()>
}

impl PythonRouter {
    pub fn new() -> PythonRouter {
        PythonRouter {
            _priv: PhantomData,
        }
    }
}

fn use_router<F: Fn(&mut PythonEnvironment)>(with: F) {
    let now = Instant::now();
    unsafe {
        if PYTHON_ROUTER.is_none() {
            PYTHON_ROUTER = Some(Arc::new(Mutex::new(PythonEnvironment::new())))
        }

        if let &Some(ref arc) = &PYTHON_ROUTER {
            debug_println!("Asking Python Router lock");
            use_item!(mut arc, with(&mut arc));
            debug_println!("Releasing Python Router lock");
        }
    }

    let nower_now = Instant::now();

    println!("Router actions took: {:#?}", nower_now - now);
}

enum RouterEvent {
    Message(Message),
    Packet(Bytes),
}

impl Router<PythonRouter> for PythonRouter {
    fn start(&mut self) {
        use_router(|r| {
            r.run(r#"
def print_some_bytes(bw, x):
    try:
        bw.print("Got packet with length of %d" % len(x))
    except:
        bw.print("Died trying to get len :( %s" % x)

bw.add_packet_handler(print_some_bytes)
            "#);
        })
    }

    fn handle_message(&mut self, message: Message) {
        use_router(|r| {
            r.run("print('Achter')");
            r.run("import bw\nbw.run_rust_func('Achter')");
        })
    }

    fn handle_packet(&mut self, packet: Bytes) {
        use_router(|r| {
            let gil = Python::acquire_gil();
            let py = gil.python();

            let bytes = PyBytes::new(py, &packet);

            let mut x = None;

            for ref cb in &r.on_packet_cb {
                x = Some(cb.call1(py, (&r.bw_module, &bytes,)));
            }

            if let Some(Err(x)) = x {
                match x.pvalue {
                    PyErrValue::Value(n) => {
                        {
                            let globals: &PyDict = r.globals.extract(py).unwrap();
                            globals.set_item("last_error", n);
                        }

                        r.run("bw.print('Got an error: %s' % str(last_error))");
                    },

                    _ => {}
                }
            }
        });
    }
}

#[py::modinit(bw)]
fn init_module(py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m, "print")]
    fn print(data: String) -> PyResult<()>  {
        println!("From python: {}", data);

        Ok(())
    }

    #[pyfn(m, "add_message_handler")]
    fn register_on_message(py: Python, callback: PyObject) -> PyResult<()> {
        thread::spawn(move || {
            use_router(|r| {
                let gil = Python::acquire_gil();
                let py = gil.python();

                r.on_message_cb.push(callback.clone_ref(py));
            });
        });

        Ok(())
    }

    #[pyfn(m, "add_packet_handler")]
    fn register_on_packet(py: Python, callback: PyObject) -> PyResult<()> {
        thread::spawn(move || {
            debug_println!("Adding new packet handler");
            use_router(|r| {
                let gil = Python::acquire_gil();
                let py = gil.python();

                r.on_packet_cb.push(callback.clone_ref(py));
            });
        });

        Ok(())
    }

    Ok(())
}