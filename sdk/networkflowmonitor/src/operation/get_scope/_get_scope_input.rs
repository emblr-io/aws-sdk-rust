// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetScopeInput {
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account. A scope ID is returned from a <code>CreateScope</code> API call.</p>
    pub scope_id: ::std::option::Option<::std::string::String>,
}
impl GetScopeInput {
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account. A scope ID is returned from a <code>CreateScope</code> API call.</p>
    pub fn scope_id(&self) -> ::std::option::Option<&str> {
        self.scope_id.as_deref()
    }
}
impl GetScopeInput {
    /// Creates a new builder-style object to manufacture [`GetScopeInput`](crate::operation::get_scope::GetScopeInput).
    pub fn builder() -> crate::operation::get_scope::builders::GetScopeInputBuilder {
        crate::operation::get_scope::builders::GetScopeInputBuilder::default()
    }
}

/// A builder for [`GetScopeInput`](crate::operation::get_scope::GetScopeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetScopeInputBuilder {
    pub(crate) scope_id: ::std::option::Option<::std::string::String>,
}
impl GetScopeInputBuilder {
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account. A scope ID is returned from a <code>CreateScope</code> API call.</p>
    /// This field is required.
    pub fn scope_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scope_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account. A scope ID is returned from a <code>CreateScope</code> API call.</p>
    pub fn set_scope_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scope_id = input;
        self
    }
    /// <p>The identifier for the scope that includes the resources you want to get data results for. A scope ID is an internally-generated identifier that includes all the resources for a specific root account. A scope ID is returned from a <code>CreateScope</code> API call.</p>
    pub fn get_scope_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.scope_id
    }
    /// Consumes the builder and constructs a [`GetScopeInput`](crate::operation::get_scope::GetScopeInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_scope::GetScopeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_scope::GetScopeInput { scope_id: self.scope_id })
    }
}
