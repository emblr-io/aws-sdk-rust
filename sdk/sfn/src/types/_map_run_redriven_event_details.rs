// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about a Map Run that was redriven.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MapRunRedrivenEventDetails {
    /// <p>The Amazon Resource Name (ARN) of a Map Run that was redriven.</p>
    pub map_run_arn: ::std::option::Option<::std::string::String>,
    /// <p>The number of times the Map Run has been redriven at this point in the execution's history including this event. The redrive count for a redriven Map Run is always greater than 0.</p>
    pub redrive_count: ::std::option::Option<i32>,
}
impl MapRunRedrivenEventDetails {
    /// <p>The Amazon Resource Name (ARN) of a Map Run that was redriven.</p>
    pub fn map_run_arn(&self) -> ::std::option::Option<&str> {
        self.map_run_arn.as_deref()
    }
    /// <p>The number of times the Map Run has been redriven at this point in the execution's history including this event. The redrive count for a redriven Map Run is always greater than 0.</p>
    pub fn redrive_count(&self) -> ::std::option::Option<i32> {
        self.redrive_count
    }
}
impl MapRunRedrivenEventDetails {
    /// Creates a new builder-style object to manufacture [`MapRunRedrivenEventDetails`](crate::types::MapRunRedrivenEventDetails).
    pub fn builder() -> crate::types::builders::MapRunRedrivenEventDetailsBuilder {
        crate::types::builders::MapRunRedrivenEventDetailsBuilder::default()
    }
}

/// A builder for [`MapRunRedrivenEventDetails`](crate::types::MapRunRedrivenEventDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MapRunRedrivenEventDetailsBuilder {
    pub(crate) map_run_arn: ::std::option::Option<::std::string::String>,
    pub(crate) redrive_count: ::std::option::Option<i32>,
}
impl MapRunRedrivenEventDetailsBuilder {
    /// <p>The Amazon Resource Name (ARN) of a Map Run that was redriven.</p>
    pub fn map_run_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.map_run_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a Map Run that was redriven.</p>
    pub fn set_map_run_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.map_run_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a Map Run that was redriven.</p>
    pub fn get_map_run_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.map_run_arn
    }
    /// <p>The number of times the Map Run has been redriven at this point in the execution's history including this event. The redrive count for a redriven Map Run is always greater than 0.</p>
    pub fn redrive_count(mut self, input: i32) -> Self {
        self.redrive_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of times the Map Run has been redriven at this point in the execution's history including this event. The redrive count for a redriven Map Run is always greater than 0.</p>
    pub fn set_redrive_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.redrive_count = input;
        self
    }
    /// <p>The number of times the Map Run has been redriven at this point in the execution's history including this event. The redrive count for a redriven Map Run is always greater than 0.</p>
    pub fn get_redrive_count(&self) -> &::std::option::Option<i32> {
        &self.redrive_count
    }
    /// Consumes the builder and constructs a [`MapRunRedrivenEventDetails`](crate::types::MapRunRedrivenEventDetails).
    pub fn build(self) -> crate::types::MapRunRedrivenEventDetails {
        crate::types::MapRunRedrivenEventDetails {
            map_run_arn: self.map_run_arn,
            redrive_count: self.redrive_count,
        }
    }
}
