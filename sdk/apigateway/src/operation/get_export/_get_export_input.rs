// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request a new export of a RestApi for a particular Stage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetExportInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub rest_api_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Stage that will be exported.</p>
    pub stage_name: ::std::option::Option<::std::string::String>,
    /// <p>The type of export. Acceptable values are 'oas30' for OpenAPI 3.0.x and 'swagger' for Swagger/OpenAPI 2.0.</p>
    pub export_type: ::std::option::Option<::std::string::String>,
    /// <p>A key-value map of query string parameters that specify properties of the export, depending on the requested <code>exportType</code>. For <code>exportType</code> <code>oas30</code> and <code>swagger</code>, any combination of the following parameters are supported: <code>extensions='integrations'</code> or <code>extensions='apigateway'</code> will export the API with x-amazon-apigateway-integration extensions. <code>extensions='authorizers'</code> will export the API with x-amazon-apigateway-authorizer extensions. <code>postman</code> will export the API with Postman extensions, allowing for import to the Postman tool</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The content-type of the export, for example <code>application/json</code>. Currently <code>application/json</code> and <code>application/yaml</code> are supported for <code>exportType</code> of<code>oas30</code> and <code>swagger</code>. This should be specified in the <code>Accept</code> header for direct API requests.</p>
    pub accepts: ::std::option::Option<::std::string::String>,
}
impl GetExportInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn rest_api_id(&self) -> ::std::option::Option<&str> {
        self.rest_api_id.as_deref()
    }
    /// <p>The name of the Stage that will be exported.</p>
    pub fn stage_name(&self) -> ::std::option::Option<&str> {
        self.stage_name.as_deref()
    }
    /// <p>The type of export. Acceptable values are 'oas30' for OpenAPI 3.0.x and 'swagger' for Swagger/OpenAPI 2.0.</p>
    pub fn export_type(&self) -> ::std::option::Option<&str> {
        self.export_type.as_deref()
    }
    /// <p>A key-value map of query string parameters that specify properties of the export, depending on the requested <code>exportType</code>. For <code>exportType</code> <code>oas30</code> and <code>swagger</code>, any combination of the following parameters are supported: <code>extensions='integrations'</code> or <code>extensions='apigateway'</code> will export the API with x-amazon-apigateway-integration extensions. <code>extensions='authorizers'</code> will export the API with x-amazon-apigateway-authorizer extensions. <code>postman</code> will export the API with Postman extensions, allowing for import to the Postman tool</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.parameters.as_ref()
    }
    /// <p>The content-type of the export, for example <code>application/json</code>. Currently <code>application/json</code> and <code>application/yaml</code> are supported for <code>exportType</code> of<code>oas30</code> and <code>swagger</code>. This should be specified in the <code>Accept</code> header for direct API requests.</p>
    pub fn accepts(&self) -> ::std::option::Option<&str> {
        self.accepts.as_deref()
    }
}
impl GetExportInput {
    /// Creates a new builder-style object to manufacture [`GetExportInput`](crate::operation::get_export::GetExportInput).
    pub fn builder() -> crate::operation::get_export::builders::GetExportInputBuilder {
        crate::operation::get_export::builders::GetExportInputBuilder::default()
    }
}

/// A builder for [`GetExportInput`](crate::operation::get_export::GetExportInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetExportInputBuilder {
    pub(crate) rest_api_id: ::std::option::Option<::std::string::String>,
    pub(crate) stage_name: ::std::option::Option<::std::string::String>,
    pub(crate) export_type: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) accepts: ::std::option::Option<::std::string::String>,
}
impl GetExportInputBuilder {
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
    /// <p>The name of the Stage that will be exported.</p>
    /// This field is required.
    pub fn stage_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stage_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Stage that will be exported.</p>
    pub fn set_stage_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stage_name = input;
        self
    }
    /// <p>The name of the Stage that will be exported.</p>
    pub fn get_stage_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stage_name
    }
    /// <p>The type of export. Acceptable values are 'oas30' for OpenAPI 3.0.x and 'swagger' for Swagger/OpenAPI 2.0.</p>
    /// This field is required.
    pub fn export_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.export_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of export. Acceptable values are 'oas30' for OpenAPI 3.0.x and 'swagger' for Swagger/OpenAPI 2.0.</p>
    pub fn set_export_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.export_type = input;
        self
    }
    /// <p>The type of export. Acceptable values are 'oas30' for OpenAPI 3.0.x and 'swagger' for Swagger/OpenAPI 2.0.</p>
    pub fn get_export_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.export_type
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>A key-value map of query string parameters that specify properties of the export, depending on the requested <code>exportType</code>. For <code>exportType</code> <code>oas30</code> and <code>swagger</code>, any combination of the following parameters are supported: <code>extensions='integrations'</code> or <code>extensions='apigateway'</code> will export the API with x-amazon-apigateway-integration extensions. <code>extensions='authorizers'</code> will export the API with x-amazon-apigateway-authorizer extensions. <code>postman</code> will export the API with Postman extensions, allowing for import to the Postman tool</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A key-value map of query string parameters that specify properties of the export, depending on the requested <code>exportType</code>. For <code>exportType</code> <code>oas30</code> and <code>swagger</code>, any combination of the following parameters are supported: <code>extensions='integrations'</code> or <code>extensions='apigateway'</code> will export the API with x-amazon-apigateway-integration extensions. <code>extensions='authorizers'</code> will export the API with x-amazon-apigateway-authorizer extensions. <code>postman</code> will export the API with Postman extensions, allowing for import to the Postman tool</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>A key-value map of query string parameters that specify properties of the export, depending on the requested <code>exportType</code>. For <code>exportType</code> <code>oas30</code> and <code>swagger</code>, any combination of the following parameters are supported: <code>extensions='integrations'</code> or <code>extensions='apigateway'</code> will export the API with x-amazon-apigateway-integration extensions. <code>extensions='authorizers'</code> will export the API with x-amazon-apigateway-authorizer extensions. <code>postman</code> will export the API with Postman extensions, allowing for import to the Postman tool</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.parameters
    }
    /// <p>The content-type of the export, for example <code>application/json</code>. Currently <code>application/json</code> and <code>application/yaml</code> are supported for <code>exportType</code> of<code>oas30</code> and <code>swagger</code>. This should be specified in the <code>Accept</code> header for direct API requests.</p>
    pub fn accepts(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accepts = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content-type of the export, for example <code>application/json</code>. Currently <code>application/json</code> and <code>application/yaml</code> are supported for <code>exportType</code> of<code>oas30</code> and <code>swagger</code>. This should be specified in the <code>Accept</code> header for direct API requests.</p>
    pub fn set_accepts(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accepts = input;
        self
    }
    /// <p>The content-type of the export, for example <code>application/json</code>. Currently <code>application/json</code> and <code>application/yaml</code> are supported for <code>exportType</code> of<code>oas30</code> and <code>swagger</code>. This should be specified in the <code>Accept</code> header for direct API requests.</p>
    pub fn get_accepts(&self) -> &::std::option::Option<::std::string::String> {
        &self.accepts
    }
    /// Consumes the builder and constructs a [`GetExportInput`](crate::operation::get_export::GetExportInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_export::GetExportInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_export::GetExportInput {
            rest_api_id: self.rest_api_id,
            stage_name: self.stage_name,
            export_type: self.export_type,
            parameters: self.parameters,
            accepts: self.accepts,
        })
    }
}
