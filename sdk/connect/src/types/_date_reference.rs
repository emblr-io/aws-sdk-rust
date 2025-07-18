// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a reference when the <code>referenceType</code> is <code>DATE</code>. Otherwise, null.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DateReference {
    /// <p>Identifier of the date reference.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A valid date.</p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl DateReference {
    /// <p>Identifier of the date reference.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A valid date.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl DateReference {
    /// Creates a new builder-style object to manufacture [`DateReference`](crate::types::DateReference).
    pub fn builder() -> crate::types::builders::DateReferenceBuilder {
        crate::types::builders::DateReferenceBuilder::default()
    }
}

/// A builder for [`DateReference`](crate::types::DateReference).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DateReferenceBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl DateReferenceBuilder {
    /// <p>Identifier of the date reference.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier of the date reference.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Identifier of the date reference.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A valid date.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A valid date.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>A valid date.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`DateReference`](crate::types::DateReference).
    pub fn build(self) -> crate::types::DateReference {
        crate::types::DateReference {
            name: self.name,
            value: self.value,
        }
    }
}
