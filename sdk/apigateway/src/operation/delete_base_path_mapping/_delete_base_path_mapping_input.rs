// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to delete the BasePathMapping resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteBasePathMappingInput {
    /// <p>The domain name of the BasePathMapping resource to delete.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the domain name resource. Supported only for private custom domain names.</p>
    pub domain_name_id: ::std::option::Option<::std::string::String>,
    /// <p>The base path name of the BasePathMapping resource to delete.</p>
    /// <p>To specify an empty base path, set this parameter to <code>'(none)'</code>.</p>
    pub base_path: ::std::option::Option<::std::string::String>,
}
impl DeleteBasePathMappingInput {
    /// <p>The domain name of the BasePathMapping resource to delete.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The identifier for the domain name resource. Supported only for private custom domain names.</p>
    pub fn domain_name_id(&self) -> ::std::option::Option<&str> {
        self.domain_name_id.as_deref()
    }
    /// <p>The base path name of the BasePathMapping resource to delete.</p>
    /// <p>To specify an empty base path, set this parameter to <code>'(none)'</code>.</p>
    pub fn base_path(&self) -> ::std::option::Option<&str> {
        self.base_path.as_deref()
    }
}
impl DeleteBasePathMappingInput {
    /// Creates a new builder-style object to manufacture [`DeleteBasePathMappingInput`](crate::operation::delete_base_path_mapping::DeleteBasePathMappingInput).
    pub fn builder() -> crate::operation::delete_base_path_mapping::builders::DeleteBasePathMappingInputBuilder {
        crate::operation::delete_base_path_mapping::builders::DeleteBasePathMappingInputBuilder::default()
    }
}

/// A builder for [`DeleteBasePathMappingInput`](crate::operation::delete_base_path_mapping::DeleteBasePathMappingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteBasePathMappingInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) domain_name_id: ::std::option::Option<::std::string::String>,
    pub(crate) base_path: ::std::option::Option<::std::string::String>,
}
impl DeleteBasePathMappingInputBuilder {
    /// <p>The domain name of the BasePathMapping resource to delete.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain name of the BasePathMapping resource to delete.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The domain name of the BasePathMapping resource to delete.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The identifier for the domain name resource. Supported only for private custom domain names.</p>
    pub fn domain_name_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the domain name resource. Supported only for private custom domain names.</p>
    pub fn set_domain_name_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name_id = input;
        self
    }
    /// <p>The identifier for the domain name resource. Supported only for private custom domain names.</p>
    pub fn get_domain_name_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name_id
    }
    /// <p>The base path name of the BasePathMapping resource to delete.</p>
    /// <p>To specify an empty base path, set this parameter to <code>'(none)'</code>.</p>
    /// This field is required.
    pub fn base_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.base_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The base path name of the BasePathMapping resource to delete.</p>
    /// <p>To specify an empty base path, set this parameter to <code>'(none)'</code>.</p>
    pub fn set_base_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.base_path = input;
        self
    }
    /// <p>The base path name of the BasePathMapping resource to delete.</p>
    /// <p>To specify an empty base path, set this parameter to <code>'(none)'</code>.</p>
    pub fn get_base_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.base_path
    }
    /// Consumes the builder and constructs a [`DeleteBasePathMappingInput`](crate::operation::delete_base_path_mapping::DeleteBasePathMappingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_base_path_mapping::DeleteBasePathMappingInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_base_path_mapping::DeleteBasePathMappingInput {
            domain_name: self.domain_name,
            domain_name_id: self.domain_name_id,
            base_path: self.base_path,
        })
    }
}
