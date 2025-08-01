// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a simulation software suite.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SimulationSoftwareSuite {
    /// <p>The name of the simulation software suite. <code>SimulationRuntime</code> is the only supported value.</p>
    pub name: ::std::option::Option<crate::types::SimulationSoftwareSuiteType>,
    /// <p>The version of the simulation software suite. Not applicable for <code>SimulationRuntime</code>.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl SimulationSoftwareSuite {
    /// <p>The name of the simulation software suite. <code>SimulationRuntime</code> is the only supported value.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::SimulationSoftwareSuiteType> {
        self.name.as_ref()
    }
    /// <p>The version of the simulation software suite. Not applicable for <code>SimulationRuntime</code>.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl SimulationSoftwareSuite {
    /// Creates a new builder-style object to manufacture [`SimulationSoftwareSuite`](crate::types::SimulationSoftwareSuite).
    pub fn builder() -> crate::types::builders::SimulationSoftwareSuiteBuilder {
        crate::types::builders::SimulationSoftwareSuiteBuilder::default()
    }
}

/// A builder for [`SimulationSoftwareSuite`](crate::types::SimulationSoftwareSuite).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SimulationSoftwareSuiteBuilder {
    pub(crate) name: ::std::option::Option<crate::types::SimulationSoftwareSuiteType>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl SimulationSoftwareSuiteBuilder {
    /// <p>The name of the simulation software suite. <code>SimulationRuntime</code> is the only supported value.</p>
    pub fn name(mut self, input: crate::types::SimulationSoftwareSuiteType) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the simulation software suite. <code>SimulationRuntime</code> is the only supported value.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::SimulationSoftwareSuiteType>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the simulation software suite. <code>SimulationRuntime</code> is the only supported value.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::SimulationSoftwareSuiteType> {
        &self.name
    }
    /// <p>The version of the simulation software suite. Not applicable for <code>SimulationRuntime</code>.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the simulation software suite. Not applicable for <code>SimulationRuntime</code>.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the simulation software suite. Not applicable for <code>SimulationRuntime</code>.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`SimulationSoftwareSuite`](crate::types::SimulationSoftwareSuite).
    pub fn build(self) -> crate::types::SimulationSoftwareSuite {
        crate::types::SimulationSoftwareSuite {
            name: self.name,
            version: self.version,
        }
    }
}
