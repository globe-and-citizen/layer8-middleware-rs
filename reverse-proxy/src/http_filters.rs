use std::any::Any;

use pingora::modules::http::{HttpModule, HttpModuleBuilder, ModuleBuilder};

enum HttpFiltersOrder {
    Websocket,
    EncryptedResponse,
}

pub mod encrypted_response_module {
    use super::*;

    pub struct EncryptedResponseModule;

    impl EncryptedResponseModule {
        pub fn module() -> ModuleBuilder {
            Box::new(EncryptedResponseModule)
        }
    }

    impl HttpModuleBuilder for EncryptedResponseModule {
        fn init(&self) -> pingora::modules::http::Module {
            Box::new(EncryptedResponseModule)
        }

        fn order(&self) -> i16 {
            HttpFiltersOrder::EncryptedResponse as i16
        }
    }

    impl HttpModule for EncryptedResponseModule {
        fn as_any(&self) -> &dyn Any {
            self as &dyn Any
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self as &mut dyn Any
        }
    }
}
