// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about an iteration of a Map state.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MapIterationEventDetails {
    /// <p>The name of the iteration’s parent Map state.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The index of the array belonging to the Map state iteration.</p>
    pub index: i32,
}
impl MapIterationEventDetails {
    /// <p>The name of the iteration’s parent Map state.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The index of the array belonging to the Map state iteration.</p>
    pub fn index(&self) -> i32 {
        self.index
    }
}
impl MapIterationEventDetails {
    /// Creates a new builder-style object to manufacture [`MapIterationEventDetails`](crate::types::MapIterationEventDetails).
    pub fn builder() -> crate::types::builders::MapIterationEventDetailsBuilder {
        crate::types::builders::MapIterationEventDetailsBuilder::default()
    }
}

/// A builder for [`MapIterationEventDetails`](crate::types::MapIterationEventDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MapIterationEventDetailsBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) index: ::std::option::Option<i32>,
}
impl MapIterationEventDetailsBuilder {
    /// <p>The name of the iteration’s parent Map state.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the iteration’s parent Map state.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the iteration’s parent Map state.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The index of the array belonging to the Map state iteration.</p>
    pub fn index(mut self, input: i32) -> Self {
        self.index = ::std::option::Option::Some(input);
        self
    }
    /// <p>The index of the array belonging to the Map state iteration.</p>
    pub fn set_index(mut self, input: ::std::option::Option<i32>) -> Self {
        self.index = input;
        self
    }
    /// <p>The index of the array belonging to the Map state iteration.</p>
    pub fn get_index(&self) -> &::std::option::Option<i32> {
        &self.index
    }
    /// Consumes the builder and constructs a [`MapIterationEventDetails`](crate::types::MapIterationEventDetails).
    pub fn build(self) -> crate::types::MapIterationEventDetails {
        crate::types::MapIterationEventDetails {
            name: self.name,
            index: self.index.unwrap_or_default(),
        }
    }
}
