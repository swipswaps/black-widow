use super::super::prelude::*;
use pyo3::prelude::*;
use pyo3::prepare_freethreaded_python;
use std::net::{SocketAddr, IpAddr};
use std::sync::{Mutex, Arc};
use std::marker::PhantomData;

static mut PYTHON_ROUTER: Option<Arc<Mutex<PythonEnvironment>>> = None;

pub struct PythonEnvironment {
    queue_fn: Option<fn(ServerEvent)>
}

impl PythonEnvironment {
    fn queue(&self, event: ServerEvent) {
        if let &Some(ref qfn) = &self.queue_fn {
            (qfn)(event);
        }
    }

    fn new() -> PythonEnvironment {
        prepare_freethreaded_python();

        let gil = Python::acquire_gil();
        let py = gil.python();
        let m = PyModule::new(py, "bw").unwrap();
        init_module(py, m);
        let x = PyDict::new(py);

        x.set_item("bw", m);


        println!("{:?}, set global: {:?}", m, py.eval("bw.run_rust_func(\"oh\")", None, Some(x)).is_ok());

        PythonEnvironment {
            queue_fn: None
        }
    }

    fn run(&mut self, script: &str) -> PyResult<()> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        if py.eval("bw.run_rust_func('Help1')", None, None).is_err() {
            println!("I am cry");
        }

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

fn use_router<F: Fn(&mut PythonEnvironment)>(with: F)  {
    unsafe {
        if PYTHON_ROUTER.is_none() {
            PYTHON_ROUTER = Some(Arc::new(Mutex::new(PythonEnvironment::new())))
        }

        if let &Some(ref arc) = &PYTHON_ROUTER {
            use_item!(mut arc, with(&mut arc));
        }
    }
}

enum RouterEvent {
    Message(Message),
    Packet(Bytes),
}

impl Router<PythonRouter> for PythonRouter {
    fn start(&mut self, cb: fn(ServerEvent)) {
        use_router(|r| {
            r.queue_fn = Some(cb);
        });
    }

    fn handle_message(&mut self, message: Message) {
        use_router(|r| {
            r.run("print('Achter')");
            r.run("import bw\nbw.run_rust_func('Achter')");
        })
    }

    fn handle_packet(&mut self, packet: Bytes) {
        use_router(|r| {
            r.run("print('Achter')");
            r.run("import bw\nbw.run_rust_func('Achter')");
        })
    }
}

#[py::modinit(bw)]
fn init_module(py: Python, m: &PyModule) -> PyResult<()> {

    // pyo3 aware function. All of our python interface could be declared
    // in a separate module.
    // Note that the `#[pyfn()]` annotation automatically converts the arguments from
    // Python objects to Rust values; and the Rust return value back into a Python object.
    #[pyfn(m, "run_rust_func")]
    fn run(name: &PyString) -> PyResult<()> {
        println!("Rust says: Hello {} of Python!", name);
        Ok(())
    }

    Ok(())
}