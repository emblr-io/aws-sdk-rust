// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportSchemaOutput {
    #[allow(missing_docs)] // documentation missing in model
    pub content: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub schema_arn: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub schema_name: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub schema_version: ::std::option::Option<::std::string::String>,
    #[allow(missing_docs)] // documentation missing in model
    pub r#type: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ExportSchemaOutput {
    #[allow(missing_docs)] // documentation missing in model
    pub fn content(&self) -> ::std::option::Option<&str> {
        self.content.as_deref()
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn schema_arn(&self) -> ::std::option::Option<&str> {
        self.schema_arn.as_deref()
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn schema_name(&self) -> ::std::option::Option<&str> {
        self.schema_name.as_deref()
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn schema_version(&self) -> ::std::option::Option<&str> {
        self.schema_version.as_deref()
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ExportSchemaOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ExportSchemaOutput {
    /// Creates a new builder-style object to manufacture [`ExportSchemaOutput`](crate::operation::export_schema::ExportSchemaOutput).
    pub fn builder() -> crate::operation::export_schema::builders::ExportSchemaOutputBuilder {
        crate::operation::export_schema::builders::ExportSchemaOutputBuilder::default()
    }
}

/// A builder for [`ExportSchemaOutput`](crate::operation::export_schema::ExportSchemaOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportSchemaOutputBuilder {
    pub(crate) content: ::std::option::Option<::std::string::String>,
    pub(crate) schema_arn: ::std::option::Option<::std::string::String>,
    pub(crate) schema_name: ::std::option::Option<::std::string::String>,
    pub(crate) schema_version: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ExportSchemaOutputBuilder {
    #[allow(missing_docs)] // documentation missing in model
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn schema_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_arn = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_schema_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_arn = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_schema_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_arn
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn schema_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_name = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_schema_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_name = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_schema_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_name
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn schema_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_version = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_schema_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_version = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_schema_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_version
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ExportSchemaOutput`](crate::operation::export_schema::ExportSchemaOutput).
    pub fn build(self) -> crate::operation::export_schema::ExportSchemaOutput {
        crate::operation::export_schema::ExportSchemaOutput {
            content: self.content,
            schema_arn: self.schema_arn,
            schema_name: self.schema_name,
            schema_version: self.schema_version,
            r#type: self.r#type,
            _request_id: self._request_id,
        }
    }
}
