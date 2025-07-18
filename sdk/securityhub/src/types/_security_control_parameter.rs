// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A parameter that a security control accepts.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SecurityControlParameter {
    /// <p>The name of a</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The current value of a control parameter.</p>
    pub value: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SecurityControlParameter {
    /// <p>The name of a</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The current value of a control parameter.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.value.is_none()`.
    pub fn value(&self) -> &[::std::string::String] {
        self.value.as_deref().unwrap_or_default()
    }
}
impl SecurityControlParameter {
    /// Creates a new builder-style object to manufacture [`SecurityControlParameter`](crate::types::SecurityControlParameter).
    pub fn builder() -> crate::types::builders::SecurityControlParameterBuilder {
        crate::types::builders::SecurityControlParameterBuilder::default()
    }
}

/// A builder for [`SecurityControlParameter`](crate::types::SecurityControlParameter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SecurityControlParameterBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SecurityControlParameterBuilder {
    /// <p>The name of a</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of a</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `value`.
    ///
    /// To override the contents of this collection use [`set_value`](Self::set_value).
    ///
    /// <p>The current value of a control parameter.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.value.unwrap_or_default();
        v.push(input.into());
        self.value = ::std::option::Option::Some(v);
        self
    }
    /// <p>The current value of a control parameter.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.value = input;
        self
    }
    /// <p>The current value of a control parameter.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.value
    }
    /// Consumes the builder and constructs a [`SecurityControlParameter`](crate::types::SecurityControlParameter).
    pub fn build(self) -> crate::types::SecurityControlParameter {
        crate::types::SecurityControlParameter {
            name: self.name,
            value: self.value,
        }
    }
}
