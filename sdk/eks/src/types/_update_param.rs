// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing the details of an update request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateParam {
    /// <p>The keys associated with an update request.</p>
    pub r#type: ::std::option::Option<crate::types::UpdateParamType>,
    /// <p>The value of the keys submitted as part of an update request.</p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl UpdateParam {
    /// <p>The keys associated with an update request.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::UpdateParamType> {
        self.r#type.as_ref()
    }
    /// <p>The value of the keys submitted as part of an update request.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl UpdateParam {
    /// Creates a new builder-style object to manufacture [`UpdateParam`](crate::types::UpdateParam).
    pub fn builder() -> crate::types::builders::UpdateParamBuilder {
        crate::types::builders::UpdateParamBuilder::default()
    }
}

/// A builder for [`UpdateParam`](crate::types::UpdateParam).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateParamBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::UpdateParamType>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl UpdateParamBuilder {
    /// <p>The keys associated with an update request.</p>
    pub fn r#type(mut self, input: crate::types::UpdateParamType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The keys associated with an update request.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::UpdateParamType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The keys associated with an update request.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::UpdateParamType> {
        &self.r#type
    }
    /// <p>The value of the keys submitted as part of an update request.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the keys submitted as part of an update request.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the keys submitted as part of an update request.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`UpdateParam`](crate::types::UpdateParam).
    pub fn build(self) -> crate::types::UpdateParam {
        crate::types::UpdateParam {
            r#type: self.r#type,
            value: self.value,
        }
    }
}
