// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRetrieverOutput {
    /// <p>The identifier of the Amazon Q Business application using the retriever.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the retriever.</p>
    pub retriever_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role associated with the retriever.</p>
    pub retriever_arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of the retriever.</p>
    pub r#type: ::std::option::Option<crate::types::RetrieverType>,
    /// <p>The status of the retriever.</p>
    pub status: ::std::option::Option<crate::types::RetrieverStatus>,
    /// <p>The name of the retriever.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>Provides information on how the retriever used for your Amazon Q Business application is configured.</p>
    pub configuration: ::std::option::Option<crate::types::RetrieverConfiguration>,
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the retriever and required resources.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Unix timestamp when the retriever was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Unix timestamp when the retriever was last updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetRetrieverOutput {
    /// <p>The identifier of the Amazon Q Business application using the retriever.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The identifier of the retriever.</p>
    pub fn retriever_id(&self) -> ::std::option::Option<&str> {
        self.retriever_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role associated with the retriever.</p>
    pub fn retriever_arn(&self) -> ::std::option::Option<&str> {
        self.retriever_arn.as_deref()
    }
    /// <p>The type of the retriever.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::RetrieverType> {
        self.r#type.as_ref()
    }
    /// <p>The status of the retriever.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::RetrieverStatus> {
        self.status.as_ref()
    }
    /// <p>The name of the retriever.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>Provides information on how the retriever used for your Amazon Q Business application is configured.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::RetrieverConfiguration> {
        self.configuration.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the retriever and required resources.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The Unix timestamp when the retriever was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The Unix timestamp when the retriever was last updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetRetrieverOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRetrieverOutput {
    /// Creates a new builder-style object to manufacture [`GetRetrieverOutput`](crate::operation::get_retriever::GetRetrieverOutput).
    pub fn builder() -> crate::operation::get_retriever::builders::GetRetrieverOutputBuilder {
        crate::operation::get_retriever::builders::GetRetrieverOutputBuilder::default()
    }
}

/// A builder for [`GetRetrieverOutput`](crate::operation::get_retriever::GetRetrieverOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRetrieverOutputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) retriever_id: ::std::option::Option<::std::string::String>,
    pub(crate) retriever_arn: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::RetrieverType>,
    pub(crate) status: ::std::option::Option<crate::types::RetrieverStatus>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) configuration: ::std::option::Option<crate::types::RetrieverConfiguration>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetRetrieverOutputBuilder {
    /// <p>The identifier of the Amazon Q Business application using the retriever.</p>
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Q Business application using the retriever.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The identifier of the Amazon Q Business application using the retriever.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The identifier of the retriever.</p>
    pub fn retriever_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.retriever_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the retriever.</p>
    pub fn set_retriever_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.retriever_id = input;
        self
    }
    /// <p>The identifier of the retriever.</p>
    pub fn get_retriever_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.retriever_id
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role associated with the retriever.</p>
    pub fn retriever_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.retriever_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role associated with the retriever.</p>
    pub fn set_retriever_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.retriever_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role associated with the retriever.</p>
    pub fn get_retriever_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.retriever_arn
    }
    /// <p>The type of the retriever.</p>
    pub fn r#type(mut self, input: crate::types::RetrieverType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the retriever.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RetrieverType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the retriever.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RetrieverType> {
        &self.r#type
    }
    /// <p>The status of the retriever.</p>
    pub fn status(mut self, input: crate::types::RetrieverStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the retriever.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::RetrieverStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the retriever.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::RetrieverStatus> {
        &self.status
    }
    /// <p>The name of the retriever.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the retriever.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The name of the retriever.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>Provides information on how the retriever used for your Amazon Q Business application is configured.</p>
    pub fn configuration(mut self, input: crate::types::RetrieverConfiguration) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides information on how the retriever used for your Amazon Q Business application is configured.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::RetrieverConfiguration>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>Provides information on how the retriever used for your Amazon Q Business application is configured.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::RetrieverConfiguration> {
        &self.configuration
    }
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the retriever and required resources.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the retriever and required resources.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role with the permission to access the retriever and required resources.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The Unix timestamp when the retriever was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp when the retriever was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The Unix timestamp when the retriever was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The Unix timestamp when the retriever was last updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp when the retriever was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The Unix timestamp when the retriever was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRetrieverOutput`](crate::operation::get_retriever::GetRetrieverOutput).
    pub fn build(self) -> crate::operation::get_retriever::GetRetrieverOutput {
        crate::operation::get_retriever::GetRetrieverOutput {
            application_id: self.application_id,
            retriever_id: self.retriever_id,
            retriever_arn: self.retriever_arn,
            r#type: self.r#type,
            status: self.status,
            display_name: self.display_name,
            configuration: self.configuration,
            role_arn: self.role_arn,
            created_at: self.created_at,
            updated_at: self.updated_at,
            _request_id: self._request_id,
        }
    }
}
