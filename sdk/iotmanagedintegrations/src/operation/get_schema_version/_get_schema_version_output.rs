// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSchemaVersionOutput {
    /// <p>The id of the schema version.</p>
    pub schema_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of schema version.</p>
    pub r#type: ::std::option::Option<crate::types::SchemaVersionType>,
    /// <p>The description of the schema version.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The name of the schema version.</p>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>The schema version. If this is left blank, it defaults to the latest version.</p>
    pub semantic_version: ::std::option::Option<::std::string::String>,
    /// <p>The visibility of the schema version.</p>
    pub visibility: ::std::option::Option<crate::types::SchemaVersionVisibility>,
    /// <p>The schema of the schema version.</p>
    pub schema: ::std::option::Option<::aws_smithy_types::Document>,
    _request_id: Option<String>,
}
impl GetSchemaVersionOutput {
    /// <p>The id of the schema version.</p>
    pub fn schema_id(&self) -> ::std::option::Option<&str> {
        self.schema_id.as_deref()
    }
    /// <p>The type of schema version.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::SchemaVersionType> {
        self.r#type.as_ref()
    }
    /// <p>The description of the schema version.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The name of the schema version.</p>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>The schema version. If this is left blank, it defaults to the latest version.</p>
    pub fn semantic_version(&self) -> ::std::option::Option<&str> {
        self.semantic_version.as_deref()
    }
    /// <p>The visibility of the schema version.</p>
    pub fn visibility(&self) -> ::std::option::Option<&crate::types::SchemaVersionVisibility> {
        self.visibility.as_ref()
    }
    /// <p>The schema of the schema version.</p>
    pub fn schema(&self) -> ::std::option::Option<&::aws_smithy_types::Document> {
        self.schema.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetSchemaVersionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSchemaVersionOutput {
    /// Creates a new builder-style object to manufacture [`GetSchemaVersionOutput`](crate::operation::get_schema_version::GetSchemaVersionOutput).
    pub fn builder() -> crate::operation::get_schema_version::builders::GetSchemaVersionOutputBuilder {
        crate::operation::get_schema_version::builders::GetSchemaVersionOutputBuilder::default()
    }
}

/// A builder for [`GetSchemaVersionOutput`](crate::operation::get_schema_version::GetSchemaVersionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSchemaVersionOutputBuilder {
    pub(crate) schema_id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::SchemaVersionType>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) semantic_version: ::std::option::Option<::std::string::String>,
    pub(crate) visibility: ::std::option::Option<crate::types::SchemaVersionVisibility>,
    pub(crate) schema: ::std::option::Option<::aws_smithy_types::Document>,
    _request_id: Option<String>,
}
impl GetSchemaVersionOutputBuilder {
    /// <p>The id of the schema version.</p>
    pub fn schema_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The id of the schema version.</p>
    pub fn set_schema_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_id = input;
        self
    }
    /// <p>The id of the schema version.</p>
    pub fn get_schema_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_id
    }
    /// <p>The type of schema version.</p>
    pub fn r#type(mut self, input: crate::types::SchemaVersionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of schema version.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::SchemaVersionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of schema version.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::SchemaVersionType> {
        &self.r#type
    }
    /// <p>The description of the schema version.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the schema version.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the schema version.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The name of the schema version.</p>
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the schema version.</p>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The name of the schema version.</p>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// <p>The schema version. If this is left blank, it defaults to the latest version.</p>
    pub fn semantic_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.semantic_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The schema version. If this is left blank, it defaults to the latest version.</p>
    pub fn set_semantic_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.semantic_version = input;
        self
    }
    /// <p>The schema version. If this is left blank, it defaults to the latest version.</p>
    pub fn get_semantic_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.semantic_version
    }
    /// <p>The visibility of the schema version.</p>
    pub fn visibility(mut self, input: crate::types::SchemaVersionVisibility) -> Self {
        self.visibility = ::std::option::Option::Some(input);
        self
    }
    /// <p>The visibility of the schema version.</p>
    pub fn set_visibility(mut self, input: ::std::option::Option<crate::types::SchemaVersionVisibility>) -> Self {
        self.visibility = input;
        self
    }
    /// <p>The visibility of the schema version.</p>
    pub fn get_visibility(&self) -> &::std::option::Option<crate::types::SchemaVersionVisibility> {
        &self.visibility
    }
    /// <p>The schema of the schema version.</p>
    pub fn schema(mut self, input: ::aws_smithy_types::Document) -> Self {
        self.schema = ::std::option::Option::Some(input);
        self
    }
    /// <p>The schema of the schema version.</p>
    pub fn set_schema(mut self, input: ::std::option::Option<::aws_smithy_types::Document>) -> Self {
        self.schema = input;
        self
    }
    /// <p>The schema of the schema version.</p>
    pub fn get_schema(&self) -> &::std::option::Option<::aws_smithy_types::Document> {
        &self.schema
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSchemaVersionOutput`](crate::operation::get_schema_version::GetSchemaVersionOutput).
    pub fn build(self) -> crate::operation::get_schema_version::GetSchemaVersionOutput {
        crate::operation::get_schema_version::GetSchemaVersionOutput {
            schema_id: self.schema_id,
            r#type: self.r#type,
            description: self.description,
            namespace: self.namespace,
            semantic_version: self.semantic_version,
            visibility: self.visibility,
            schema: self.schema,
            _request_id: self._request_id,
        }
    }
}
