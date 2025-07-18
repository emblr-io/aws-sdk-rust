// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Requests API Gateway to create a new BasePathMapping resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBasePathMappingInput {
    /// <p>The domain name of the BasePathMapping resource to create.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the domain name resource. Required for private custom domain names.</p>
    pub domain_name_id: ::std::option::Option<::std::string::String>,
    /// <p>The base path name that callers of the API must provide as part of the URL after the domain name. This value must be unique for all of the mappings across a single API. Specify '(none)' if you do not want callers to specify a base path name after the domain name.</p>
    pub base_path: ::std::option::Option<::std::string::String>,
    /// <p>The string identifier of the associated RestApi.</p>
    pub rest_api_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the API's stage that you want to use for this mapping. Specify '(none)' if you want callers to explicitly specify the stage name after any base path name.</p>
    pub stage: ::std::option::Option<::std::string::String>,
}
impl CreateBasePathMappingInput {
    /// <p>The domain name of the BasePathMapping resource to create.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The identifier for the domain name resource. Required for private custom domain names.</p>
    pub fn domain_name_id(&self) -> ::std::option::Option<&str> {
        self.domain_name_id.as_deref()
    }
    /// <p>The base path name that callers of the API must provide as part of the URL after the domain name. This value must be unique for all of the mappings across a single API. Specify '(none)' if you do not want callers to specify a base path name after the domain name.</p>
    pub fn base_path(&self) -> ::std::option::Option<&str> {
        self.base_path.as_deref()
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn rest_api_id(&self) -> ::std::option::Option<&str> {
        self.rest_api_id.as_deref()
    }
    /// <p>The name of the API's stage that you want to use for this mapping. Specify '(none)' if you want callers to explicitly specify the stage name after any base path name.</p>
    pub fn stage(&self) -> ::std::option::Option<&str> {
        self.stage.as_deref()
    }
}
impl CreateBasePathMappingInput {
    /// Creates a new builder-style object to manufacture [`CreateBasePathMappingInput`](crate::operation::create_base_path_mapping::CreateBasePathMappingInput).
    pub fn builder() -> crate::operation::create_base_path_mapping::builders::CreateBasePathMappingInputBuilder {
        crate::operation::create_base_path_mapping::builders::CreateBasePathMappingInputBuilder::default()
    }
}

/// A builder for [`CreateBasePathMappingInput`](crate::operation::create_base_path_mapping::CreateBasePathMappingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBasePathMappingInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) domain_name_id: ::std::option::Option<::std::string::String>,
    pub(crate) base_path: ::std::option::Option<::std::string::String>,
    pub(crate) rest_api_id: ::std::option::Option<::std::string::String>,
    pub(crate) stage: ::std::option::Option<::std::string::String>,
}
impl CreateBasePathMappingInputBuilder {
    /// <p>The domain name of the BasePathMapping resource to create.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain name of the BasePathMapping resource to create.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The domain name of the BasePathMapping resource to create.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The identifier for the domain name resource. Required for private custom domain names.</p>
    pub fn domain_name_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the domain name resource. Required for private custom domain names.</p>
    pub fn set_domain_name_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name_id = input;
        self
    }
    /// <p>The identifier for the domain name resource. Required for private custom domain names.</p>
    pub fn get_domain_name_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name_id
    }
    /// <p>The base path name that callers of the API must provide as part of the URL after the domain name. This value must be unique for all of the mappings across a single API. Specify '(none)' if you do not want callers to specify a base path name after the domain name.</p>
    pub fn base_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.base_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The base path name that callers of the API must provide as part of the URL after the domain name. This value must be unique for all of the mappings across a single API. Specify '(none)' if you do not want callers to specify a base path name after the domain name.</p>
    pub fn set_base_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.base_path = input;
        self
    }
    /// <p>The base path name that callers of the API must provide as part of the URL after the domain name. This value must be unique for all of the mappings across a single API. Specify '(none)' if you do not want callers to specify a base path name after the domain name.</p>
    pub fn get_base_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.base_path
    }
    /// <p>The string identifier of the associated RestApi.</p>
    /// This field is required.
    pub fn rest_api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rest_api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn set_rest_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rest_api_id = input;
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn get_rest_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rest_api_id
    }
    /// <p>The name of the API's stage that you want to use for this mapping. Specify '(none)' if you want callers to explicitly specify the stage name after any base path name.</p>
    pub fn stage(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stage = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the API's stage that you want to use for this mapping. Specify '(none)' if you want callers to explicitly specify the stage name after any base path name.</p>
    pub fn set_stage(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stage = input;
        self
    }
    /// <p>The name of the API's stage that you want to use for this mapping. Specify '(none)' if you want callers to explicitly specify the stage name after any base path name.</p>
    pub fn get_stage(&self) -> &::std::option::Option<::std::string::String> {
        &self.stage
    }
    /// Consumes the builder and constructs a [`CreateBasePathMappingInput`](crate::operation::create_base_path_mapping::CreateBasePathMappingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_base_path_mapping::CreateBasePathMappingInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_base_path_mapping::CreateBasePathMappingInput {
            domain_name: self.domain_name,
            domain_name_id: self.domain_name_id,
            base_path: self.base_path,
            rest_api_id: self.rest_api_id,
            stage: self.stage,
        })
    }
}
