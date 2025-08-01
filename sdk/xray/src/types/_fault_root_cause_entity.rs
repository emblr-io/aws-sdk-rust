// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A collection of segments and corresponding subsegments associated to a trace summary fault error.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FaultRootCauseEntity {
    /// <p>The name of the entity.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The types and messages of the exceptions.</p>
    pub exceptions: ::std::option::Option<::std::vec::Vec<crate::types::RootCauseException>>,
    /// <p>A flag that denotes a remote subsegment.</p>
    pub remote: ::std::option::Option<bool>,
}
impl FaultRootCauseEntity {
    /// <p>The name of the entity.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The types and messages of the exceptions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.exceptions.is_none()`.
    pub fn exceptions(&self) -> &[crate::types::RootCauseException] {
        self.exceptions.as_deref().unwrap_or_default()
    }
    /// <p>A flag that denotes a remote subsegment.</p>
    pub fn remote(&self) -> ::std::option::Option<bool> {
        self.remote
    }
}
impl FaultRootCauseEntity {
    /// Creates a new builder-style object to manufacture [`FaultRootCauseEntity`](crate::types::FaultRootCauseEntity).
    pub fn builder() -> crate::types::builders::FaultRootCauseEntityBuilder {
        crate::types::builders::FaultRootCauseEntityBuilder::default()
    }
}

/// A builder for [`FaultRootCauseEntity`](crate::types::FaultRootCauseEntity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FaultRootCauseEntityBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) exceptions: ::std::option::Option<::std::vec::Vec<crate::types::RootCauseException>>,
    pub(crate) remote: ::std::option::Option<bool>,
}
impl FaultRootCauseEntityBuilder {
    /// <p>The name of the entity.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the entity.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the entity.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `exceptions`.
    ///
    /// To override the contents of this collection use [`set_exceptions`](Self::set_exceptions).
    ///
    /// <p>The types and messages of the exceptions.</p>
    pub fn exceptions(mut self, input: crate::types::RootCauseException) -> Self {
        let mut v = self.exceptions.unwrap_or_default();
        v.push(input);
        self.exceptions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The types and messages of the exceptions.</p>
    pub fn set_exceptions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RootCauseException>>) -> Self {
        self.exceptions = input;
        self
    }
    /// <p>The types and messages of the exceptions.</p>
    pub fn get_exceptions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RootCauseException>> {
        &self.exceptions
    }
    /// <p>A flag that denotes a remote subsegment.</p>
    pub fn remote(mut self, input: bool) -> Self {
        self.remote = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag that denotes a remote subsegment.</p>
    pub fn set_remote(mut self, input: ::std::option::Option<bool>) -> Self {
        self.remote = input;
        self
    }
    /// <p>A flag that denotes a remote subsegment.</p>
    pub fn get_remote(&self) -> &::std::option::Option<bool> {
        &self.remote
    }
    /// Consumes the builder and constructs a [`FaultRootCauseEntity`](crate::types::FaultRootCauseEntity).
    pub fn build(self) -> crate::types::FaultRootCauseEntity {
        crate::types::FaultRootCauseEntity {
            name: self.name,
            exceptions: self.exceptions,
            remote: self.remote,
        }
    }
}
