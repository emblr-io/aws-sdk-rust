// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLimitInput {
    /// <p>The unique identifier of the farm that contains the limit.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the limit to return.</p>
    pub limit_id: ::std::option::Option<::std::string::String>,
}
impl GetLimitInput {
    /// <p>The unique identifier of the farm that contains the limit.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>The unique identifier of the limit to return.</p>
    pub fn limit_id(&self) -> ::std::option::Option<&str> {
        self.limit_id.as_deref()
    }
}
impl GetLimitInput {
    /// Creates a new builder-style object to manufacture [`GetLimitInput`](crate::operation::get_limit::GetLimitInput).
    pub fn builder() -> crate::operation::get_limit::builders::GetLimitInputBuilder {
        crate::operation::get_limit::builders::GetLimitInputBuilder::default()
    }
}

/// A builder for [`GetLimitInput`](crate::operation::get_limit::GetLimitInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLimitInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) limit_id: ::std::option::Option<::std::string::String>,
}
impl GetLimitInputBuilder {
    /// <p>The unique identifier of the farm that contains the limit.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the farm that contains the limit.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The unique identifier of the farm that contains the limit.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The unique identifier of the limit to return.</p>
    /// This field is required.
    pub fn limit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.limit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the limit to return.</p>
    pub fn set_limit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.limit_id = input;
        self
    }
    /// <p>The unique identifier of the limit to return.</p>
    pub fn get_limit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.limit_id
    }
    /// Consumes the builder and constructs a [`GetLimitInput`](crate::operation::get_limit::GetLimitInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_limit::GetLimitInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_limit::GetLimitInput {
            farm_id: self.farm_id,
            limit_id: self.limit_id,
        })
    }
}
