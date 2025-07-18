// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteResolverInput {
    /// <p>The API ID.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the resolver type.</p>
    pub type_name: ::std::option::Option<::std::string::String>,
    /// <p>The resolver field name.</p>
    pub field_name: ::std::option::Option<::std::string::String>,
}
impl DeleteResolverInput {
    /// <p>The API ID.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>The name of the resolver type.</p>
    pub fn type_name(&self) -> ::std::option::Option<&str> {
        self.type_name.as_deref()
    }
    /// <p>The resolver field name.</p>
    pub fn field_name(&self) -> ::std::option::Option<&str> {
        self.field_name.as_deref()
    }
}
impl DeleteResolverInput {
    /// Creates a new builder-style object to manufacture [`DeleteResolverInput`](crate::operation::delete_resolver::DeleteResolverInput).
    pub fn builder() -> crate::operation::delete_resolver::builders::DeleteResolverInputBuilder {
        crate::operation::delete_resolver::builders::DeleteResolverInputBuilder::default()
    }
}

/// A builder for [`DeleteResolverInput`](crate::operation::delete_resolver::DeleteResolverInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteResolverInputBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) type_name: ::std::option::Option<::std::string::String>,
    pub(crate) field_name: ::std::option::Option<::std::string::String>,
}
impl DeleteResolverInputBuilder {
    /// <p>The API ID.</p>
    /// This field is required.
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API ID.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The API ID.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// <p>The name of the resolver type.</p>
    /// This field is required.
    pub fn type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resolver type.</p>
    pub fn set_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name = input;
        self
    }
    /// <p>The name of the resolver type.</p>
    pub fn get_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name
    }
    /// <p>The resolver field name.</p>
    /// This field is required.
    pub fn field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resolver field name.</p>
    pub fn set_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.field_name = input;
        self
    }
    /// <p>The resolver field name.</p>
    pub fn get_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.field_name
    }
    /// Consumes the builder and constructs a [`DeleteResolverInput`](crate::operation::delete_resolver::DeleteResolverInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_resolver::DeleteResolverInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_resolver::DeleteResolverInput {
            api_id: self.api_id,
            type_name: self.type_name,
            field_name: self.field_name,
        })
    }
}
