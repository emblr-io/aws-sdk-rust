// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutCodeBindingOutput {
    /// <p>The time and date that the code binding was created.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that code bindings were modified.</p>
    pub last_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The version number of the schema.</p>
    pub schema_version: ::std::option::Option<::std::string::String>,
    /// <p>The current status of code binding generation.</p>
    pub status: ::std::option::Option<crate::types::CodeGenerationStatus>,
    _request_id: Option<String>,
}
impl PutCodeBindingOutput {
    /// <p>The time and date that the code binding was created.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
    /// <p>The date and time that code bindings were modified.</p>
    pub fn last_modified(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified.as_ref()
    }
    /// <p>The version number of the schema.</p>
    pub fn schema_version(&self) -> ::std::option::Option<&str> {
        self.schema_version.as_deref()
    }
    /// <p>The current status of code binding generation.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::CodeGenerationStatus> {
        self.status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutCodeBindingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutCodeBindingOutput {
    /// Creates a new builder-style object to manufacture [`PutCodeBindingOutput`](crate::operation::put_code_binding::PutCodeBindingOutput).
    pub fn builder() -> crate::operation::put_code_binding::builders::PutCodeBindingOutputBuilder {
        crate::operation::put_code_binding::builders::PutCodeBindingOutputBuilder::default()
    }
}

/// A builder for [`PutCodeBindingOutput`](crate::operation::put_code_binding::PutCodeBindingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutCodeBindingOutputBuilder {
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) schema_version: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::CodeGenerationStatus>,
    _request_id: Option<String>,
}
impl PutCodeBindingOutputBuilder {
    /// <p>The time and date that the code binding was created.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time and date that the code binding was created.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The time and date that the code binding was created.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// <p>The date and time that code bindings were modified.</p>
    pub fn last_modified(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that code bindings were modified.</p>
    pub fn set_last_modified(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified = input;
        self
    }
    /// <p>The date and time that code bindings were modified.</p>
    pub fn get_last_modified(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified
    }
    /// <p>The version number of the schema.</p>
    pub fn schema_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version number of the schema.</p>
    pub fn set_schema_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_version = input;
        self
    }
    /// <p>The version number of the schema.</p>
    pub fn get_schema_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_version
    }
    /// <p>The current status of code binding generation.</p>
    pub fn status(mut self, input: crate::types::CodeGenerationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of code binding generation.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::CodeGenerationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of code binding generation.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::CodeGenerationStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutCodeBindingOutput`](crate::operation::put_code_binding::PutCodeBindingOutput).
    pub fn build(self) -> crate::operation::put_code_binding::PutCodeBindingOutput {
        crate::operation::put_code_binding::PutCodeBindingOutput {
            creation_date: self.creation_date,
            last_modified: self.last_modified,
            schema_version: self.schema_version,
            status: self.status,
            _request_id: self._request_id,
        }
    }
}
