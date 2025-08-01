// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateApplicationOutput {
    /// <p>The unique identifier assigned to the OpenSearch application.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the OpenSearch application.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the domain. See <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/index.html">Identifiers for IAM Entities </a> in <i>Using Amazon Web Services Identity and Access Management</i> for more information.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The data sources linked to the OpenSearch application.</p>
    pub data_sources: ::std::option::Option<::std::vec::Vec<crate::types::DataSource>>,
    /// <p>The IAM Identity Center settings configured for the OpenSearch application.</p>
    pub iam_identity_center_options: ::std::option::Option<crate::types::IamIdentityCenterOptions>,
    /// <p>Configuration settings for the OpenSearch application, including administrative options.</p>
    pub app_configs: ::std::option::Option<::std::vec::Vec<crate::types::AppConfig>>,
    /// <p>A list of tags attached to a domain.</p>
    pub tag_list: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The timestamp indicating when the OpenSearch application was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl CreateApplicationOutput {
    /// <p>The unique identifier assigned to the OpenSearch application.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The name of the OpenSearch application.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the domain. See <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/index.html">Identifiers for IAM Entities </a> in <i>Using Amazon Web Services Identity and Access Management</i> for more information.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The data sources linked to the OpenSearch application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_sources.is_none()`.
    pub fn data_sources(&self) -> &[crate::types::DataSource] {
        self.data_sources.as_deref().unwrap_or_default()
    }
    /// <p>The IAM Identity Center settings configured for the OpenSearch application.</p>
    pub fn iam_identity_center_options(&self) -> ::std::option::Option<&crate::types::IamIdentityCenterOptions> {
        self.iam_identity_center_options.as_ref()
    }
    /// <p>Configuration settings for the OpenSearch application, including administrative options.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.app_configs.is_none()`.
    pub fn app_configs(&self) -> &[crate::types::AppConfig] {
        self.app_configs.as_deref().unwrap_or_default()
    }
    /// <p>A list of tags attached to a domain.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_list.is_none()`.
    pub fn tag_list(&self) -> &[crate::types::Tag] {
        self.tag_list.as_deref().unwrap_or_default()
    }
    /// <p>The timestamp indicating when the OpenSearch application was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateApplicationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateApplicationOutput {
    /// Creates a new builder-style object to manufacture [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
    pub fn builder() -> crate::operation::create_application::builders::CreateApplicationOutputBuilder {
        crate::operation::create_application::builders::CreateApplicationOutputBuilder::default()
    }
}

/// A builder for [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateApplicationOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) data_sources: ::std::option::Option<::std::vec::Vec<crate::types::DataSource>>,
    pub(crate) iam_identity_center_options: ::std::option::Option<crate::types::IamIdentityCenterOptions>,
    pub(crate) app_configs: ::std::option::Option<::std::vec::Vec<crate::types::AppConfig>>,
    pub(crate) tag_list: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl CreateApplicationOutputBuilder {
    /// <p>The unique identifier assigned to the OpenSearch application.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier assigned to the OpenSearch application.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier assigned to the OpenSearch application.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the OpenSearch application.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the OpenSearch application.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the OpenSearch application.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the domain. See <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/index.html">Identifiers for IAM Entities </a> in <i>Using Amazon Web Services Identity and Access Management</i> for more information.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the domain. See <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/index.html">Identifiers for IAM Entities </a> in <i>Using Amazon Web Services Identity and Access Management</i> for more information.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the domain. See <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/index.html">Identifiers for IAM Entities </a> in <i>Using Amazon Web Services Identity and Access Management</i> for more information.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Appends an item to `data_sources`.
    ///
    /// To override the contents of this collection use [`set_data_sources`](Self::set_data_sources).
    ///
    /// <p>The data sources linked to the OpenSearch application.</p>
    pub fn data_sources(mut self, input: crate::types::DataSource) -> Self {
        let mut v = self.data_sources.unwrap_or_default();
        v.push(input);
        self.data_sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The data sources linked to the OpenSearch application.</p>
    pub fn set_data_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataSource>>) -> Self {
        self.data_sources = input;
        self
    }
    /// <p>The data sources linked to the OpenSearch application.</p>
    pub fn get_data_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataSource>> {
        &self.data_sources
    }
    /// <p>The IAM Identity Center settings configured for the OpenSearch application.</p>
    pub fn iam_identity_center_options(mut self, input: crate::types::IamIdentityCenterOptions) -> Self {
        self.iam_identity_center_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The IAM Identity Center settings configured for the OpenSearch application.</p>
    pub fn set_iam_identity_center_options(mut self, input: ::std::option::Option<crate::types::IamIdentityCenterOptions>) -> Self {
        self.iam_identity_center_options = input;
        self
    }
    /// <p>The IAM Identity Center settings configured for the OpenSearch application.</p>
    pub fn get_iam_identity_center_options(&self) -> &::std::option::Option<crate::types::IamIdentityCenterOptions> {
        &self.iam_identity_center_options
    }
    /// Appends an item to `app_configs`.
    ///
    /// To override the contents of this collection use [`set_app_configs`](Self::set_app_configs).
    ///
    /// <p>Configuration settings for the OpenSearch application, including administrative options.</p>
    pub fn app_configs(mut self, input: crate::types::AppConfig) -> Self {
        let mut v = self.app_configs.unwrap_or_default();
        v.push(input);
        self.app_configs = ::std::option::Option::Some(v);
        self
    }
    /// <p>Configuration settings for the OpenSearch application, including administrative options.</p>
    pub fn set_app_configs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AppConfig>>) -> Self {
        self.app_configs = input;
        self
    }
    /// <p>Configuration settings for the OpenSearch application, including administrative options.</p>
    pub fn get_app_configs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AppConfig>> {
        &self.app_configs
    }
    /// Appends an item to `tag_list`.
    ///
    /// To override the contents of this collection use [`set_tag_list`](Self::set_tag_list).
    ///
    /// <p>A list of tags attached to a domain.</p>
    pub fn tag_list(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tag_list.unwrap_or_default();
        v.push(input);
        self.tag_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags attached to a domain.</p>
    pub fn set_tag_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tag_list = input;
        self
    }
    /// <p>A list of tags attached to a domain.</p>
    pub fn get_tag_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tag_list
    }
    /// <p>The timestamp indicating when the OpenSearch application was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp indicating when the OpenSearch application was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp indicating when the OpenSearch application was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
    pub fn build(self) -> crate::operation::create_application::CreateApplicationOutput {
        crate::operation::create_application::CreateApplicationOutput {
            id: self.id,
            name: self.name,
            arn: self.arn,
            data_sources: self.data_sources,
            iam_identity_center_options: self.iam_identity_center_options,
            app_configs: self.app_configs,
            tag_list: self.tag_list,
            created_at: self.created_at,
            _request_id: self._request_id,
        }
    }
}
