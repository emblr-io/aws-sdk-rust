// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSolFunctionPackageInput {
    /// <p>ID of the function package.</p>
    pub vnf_pkg_id: ::std::option::Option<::std::string::String>,
}
impl GetSolFunctionPackageInput {
    /// <p>ID of the function package.</p>
    pub fn vnf_pkg_id(&self) -> ::std::option::Option<&str> {
        self.vnf_pkg_id.as_deref()
    }
}
impl GetSolFunctionPackageInput {
    /// Creates a new builder-style object to manufacture [`GetSolFunctionPackageInput`](crate::operation::get_sol_function_package::GetSolFunctionPackageInput).
    pub fn builder() -> crate::operation::get_sol_function_package::builders::GetSolFunctionPackageInputBuilder {
        crate::operation::get_sol_function_package::builders::GetSolFunctionPackageInputBuilder::default()
    }
}

/// A builder for [`GetSolFunctionPackageInput`](crate::operation::get_sol_function_package::GetSolFunctionPackageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSolFunctionPackageInputBuilder {
    pub(crate) vnf_pkg_id: ::std::option::Option<::std::string::String>,
}
impl GetSolFunctionPackageInputBuilder {
    /// <p>ID of the function package.</p>
    /// This field is required.
    pub fn vnf_pkg_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vnf_pkg_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID of the function package.</p>
    pub fn set_vnf_pkg_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vnf_pkg_id = input;
        self
    }
    /// <p>ID of the function package.</p>
    pub fn get_vnf_pkg_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vnf_pkg_id
    }
    /// Consumes the builder and constructs a [`GetSolFunctionPackageInput`](crate::operation::get_sol_function_package::GetSolFunctionPackageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_sol_function_package::GetSolFunctionPackageInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_sol_function_package::GetSolFunctionPackageInput { vnf_pkg_id: self.vnf_pkg_id })
    }
}
