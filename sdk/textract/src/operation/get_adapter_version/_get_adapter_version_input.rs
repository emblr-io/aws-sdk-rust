// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAdapterVersionInput {
    /// <p>A string specifying a unique ID for the adapter version you want to retrieve information for.</p>
    pub adapter_id: ::std::option::Option<::std::string::String>,
    /// <p>A string specifying the adapter version you want to retrieve information for.</p>
    pub adapter_version: ::std::option::Option<::std::string::String>,
}
impl GetAdapterVersionInput {
    /// <p>A string specifying a unique ID for the adapter version you want to retrieve information for.</p>
    pub fn adapter_id(&self) -> ::std::option::Option<&str> {
        self.adapter_id.as_deref()
    }
    /// <p>A string specifying the adapter version you want to retrieve information for.</p>
    pub fn adapter_version(&self) -> ::std::option::Option<&str> {
        self.adapter_version.as_deref()
    }
}
impl GetAdapterVersionInput {
    /// Creates a new builder-style object to manufacture [`GetAdapterVersionInput`](crate::operation::get_adapter_version::GetAdapterVersionInput).
    pub fn builder() -> crate::operation::get_adapter_version::builders::GetAdapterVersionInputBuilder {
        crate::operation::get_adapter_version::builders::GetAdapterVersionInputBuilder::default()
    }
}

/// A builder for [`GetAdapterVersionInput`](crate::operation::get_adapter_version::GetAdapterVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAdapterVersionInputBuilder {
    pub(crate) adapter_id: ::std::option::Option<::std::string::String>,
    pub(crate) adapter_version: ::std::option::Option<::std::string::String>,
}
impl GetAdapterVersionInputBuilder {
    /// <p>A string specifying a unique ID for the adapter version you want to retrieve information for.</p>
    /// This field is required.
    pub fn adapter_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.adapter_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string specifying a unique ID for the adapter version you want to retrieve information for.</p>
    pub fn set_adapter_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.adapter_id = input;
        self
    }
    /// <p>A string specifying a unique ID for the adapter version you want to retrieve information for.</p>
    pub fn get_adapter_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.adapter_id
    }
    /// <p>A string specifying the adapter version you want to retrieve information for.</p>
    /// This field is required.
    pub fn adapter_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.adapter_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string specifying the adapter version you want to retrieve information for.</p>
    pub fn set_adapter_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.adapter_version = input;
        self
    }
    /// <p>A string specifying the adapter version you want to retrieve information for.</p>
    pub fn get_adapter_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.adapter_version
    }
    /// Consumes the builder and constructs a [`GetAdapterVersionInput`](crate::operation::get_adapter_version::GetAdapterVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_adapter_version::GetAdapterVersionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_adapter_version::GetAdapterVersionInput {
            adapter_id: self.adapter_id,
            adapter_version: self.adapter_version,
        })
    }
}
