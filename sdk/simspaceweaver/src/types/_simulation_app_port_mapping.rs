// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A collection of TCP/UDP ports for a custom or service app.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SimulationAppPortMapping {
    /// <p>The TCP/UDP port number of the app, declared in the simulation schema. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. The source code for the app should bind to the <code>Declared</code> port.</p>
    pub declared: ::std::option::Option<i32>,
    /// <p>The TCP/UDP port number of the running app. SimSpace Weaver dynamically assigns this port number when the app starts. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. Clients connect to the app using the app's IP address and the <code>Actual</code> port number.</p>
    pub actual: ::std::option::Option<i32>,
}
impl SimulationAppPortMapping {
    /// <p>The TCP/UDP port number of the app, declared in the simulation schema. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. The source code for the app should bind to the <code>Declared</code> port.</p>
    pub fn declared(&self) -> ::std::option::Option<i32> {
        self.declared
    }
    /// <p>The TCP/UDP port number of the running app. SimSpace Weaver dynamically assigns this port number when the app starts. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. Clients connect to the app using the app's IP address and the <code>Actual</code> port number.</p>
    pub fn actual(&self) -> ::std::option::Option<i32> {
        self.actual
    }
}
impl SimulationAppPortMapping {
    /// Creates a new builder-style object to manufacture [`SimulationAppPortMapping`](crate::types::SimulationAppPortMapping).
    pub fn builder() -> crate::types::builders::SimulationAppPortMappingBuilder {
        crate::types::builders::SimulationAppPortMappingBuilder::default()
    }
}

/// A builder for [`SimulationAppPortMapping`](crate::types::SimulationAppPortMapping).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SimulationAppPortMappingBuilder {
    pub(crate) declared: ::std::option::Option<i32>,
    pub(crate) actual: ::std::option::Option<i32>,
}
impl SimulationAppPortMappingBuilder {
    /// <p>The TCP/UDP port number of the app, declared in the simulation schema. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. The source code for the app should bind to the <code>Declared</code> port.</p>
    pub fn declared(mut self, input: i32) -> Self {
        self.declared = ::std::option::Option::Some(input);
        self
    }
    /// <p>The TCP/UDP port number of the app, declared in the simulation schema. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. The source code for the app should bind to the <code>Declared</code> port.</p>
    pub fn set_declared(mut self, input: ::std::option::Option<i32>) -> Self {
        self.declared = input;
        self
    }
    /// <p>The TCP/UDP port number of the app, declared in the simulation schema. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. The source code for the app should bind to the <code>Declared</code> port.</p>
    pub fn get_declared(&self) -> &::std::option::Option<i32> {
        &self.declared
    }
    /// <p>The TCP/UDP port number of the running app. SimSpace Weaver dynamically assigns this port number when the app starts. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. Clients connect to the app using the app's IP address and the <code>Actual</code> port number.</p>
    pub fn actual(mut self, input: i32) -> Self {
        self.actual = ::std::option::Option::Some(input);
        self
    }
    /// <p>The TCP/UDP port number of the running app. SimSpace Weaver dynamically assigns this port number when the app starts. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. Clients connect to the app using the app's IP address and the <code>Actual</code> port number.</p>
    pub fn set_actual(mut self, input: ::std::option::Option<i32>) -> Self {
        self.actual = input;
        self
    }
    /// <p>The TCP/UDP port number of the running app. SimSpace Weaver dynamically assigns this port number when the app starts. SimSpace Weaver maps the <code>Declared</code> port to the <code>Actual</code> port. Clients connect to the app using the app's IP address and the <code>Actual</code> port number.</p>
    pub fn get_actual(&self) -> &::std::option::Option<i32> {
        &self.actual
    }
    /// Consumes the builder and constructs a [`SimulationAppPortMapping`](crate::types::SimulationAppPortMapping).
    pub fn build(self) -> crate::types::SimulationAppPortMapping {
        crate::types::SimulationAppPortMapping {
            declared: self.declared,
            actual: self.actual,
        }
    }
}
