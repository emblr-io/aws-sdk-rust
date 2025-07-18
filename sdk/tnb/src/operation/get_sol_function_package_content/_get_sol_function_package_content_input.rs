// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSolFunctionPackageContentInput {
    /// <p>ID of the function package.</p>
    pub vnf_pkg_id: ::std::option::Option<::std::string::String>,
    /// <p>The format of the package that you want to download from the function packages.</p>
    pub accept: ::std::option::Option<crate::types::PackageContentType>,
}
impl GetSolFunctionPackageContentInput {
    /// <p>ID of the function package.</p>
    pub fn vnf_pkg_id(&self) -> ::std::option::Option<&str> {
        self.vnf_pkg_id.as_deref()
    }
    /// <p>The format of the package that you want to download from the function packages.</p>
    pub fn accept(&self) -> ::std::option::Option<&crate::types::PackageContentType> {
        self.accept.as_ref()
    }
}
impl GetSolFunctionPackageContentInput {
    /// Creates a new builder-style object to manufacture [`GetSolFunctionPackageContentInput`](crate::operation::get_sol_function_package_content::GetSolFunctionPackageContentInput).
    pub fn builder() -> crate::operation::get_sol_function_package_content::builders::GetSolFunctionPackageContentInputBuilder {
        crate::operation::get_sol_function_package_content::builders::GetSolFunctionPackageContentInputBuilder::default()
    }
}

/// A builder for [`GetSolFunctionPackageContentInput`](crate::operation::get_sol_function_package_content::GetSolFunctionPackageContentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSolFunctionPackageContentInputBuilder {
    pub(crate) vnf_pkg_id: ::std::option::Option<::std::string::String>,
    pub(crate) accept: ::std::option::Option<crate::types::PackageContentType>,
}
impl GetSolFunctionPackageContentInputBuilder {
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
    /// <p>The format of the package that you want to download from the function packages.</p>
    /// This field is required.
    pub fn accept(mut self, input: crate::types::PackageContentType) -> Self {
        self.accept = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format of the package that you want to download from the function packages.</p>
    pub fn set_accept(mut self, input: ::std::option::Option<crate::types::PackageContentType>) -> Self {
        self.accept = input;
        self
    }
    /// <p>The format of the package that you want to download from the function packages.</p>
    pub fn get_accept(&self) -> &::std::option::Option<crate::types::PackageContentType> {
        &self.accept
    }
    /// Consumes the builder and constructs a [`GetSolFunctionPackageContentInput`](crate::operation::get_sol_function_package_content::GetSolFunctionPackageContentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_sol_function_package_content::GetSolFunctionPackageContentInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_sol_function_package_content::GetSolFunctionPackageContentInput {
            vnf_pkg_id: self.vnf_pkg_id,
            accept: self.accept,
        })
    }
}
