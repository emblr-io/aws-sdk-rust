// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use crate::operation::get_organizations_access_report::_get_organizations_access_report_output::GetOrganizationsAccessReportOutputBuilder;

pub use crate::operation::get_organizations_access_report::_get_organizations_access_report_input::GetOrganizationsAccessReportInputBuilder;

impl crate::operation::get_organizations_access_report::builders::GetOrganizationsAccessReportInputBuilder {
    /// Sends a request with this input using the given client.
    pub async fn send_with(
        self,
        client: &crate::Client,
    ) -> ::std::result::Result<
        crate::operation::get_organizations_access_report::GetOrganizationsAccessReportOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::get_organizations_access_report::GetOrganizationsAccessReportError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let mut fluent_builder = client.get_organizations_access_report();
        fluent_builder.inner = self;
        fluent_builder.send().await
    }
}
/// Fluent builder constructing a request to `GetOrganizationsAccessReport`.
///
/// <p>Retrieves the service last accessed data report for Organizations that was previously generated using the <code> <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateOrganizationsAccessReport.html">GenerateOrganizationsAccessReport</a> </code> operation. This operation retrieves the status of your report job and the report contents.</p>
/// <p>Depending on the parameters that you passed when you generated the report, the data returned could include different information. For details, see <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateOrganizationsAccessReport.html">GenerateOrganizationsAccessReport</a>.</p>
/// <p>To call this operation, you must be signed in to the management account in your organization. SCPs must be enabled for your organization root. You must have permissions to perform this operation. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html">Refining permissions using service last accessed data</a> in the <i>IAM User Guide</i>.</p>
/// <p>For each service that principals in an account (root user, IAM users, or IAM roles) could access using SCPs, the operation returns details about the most recent access attempt. If there was no attempt, the service is listed without details about the most recent attempt to access the service. If the operation fails, it returns the reason that it failed.</p>
/// <p>By default, the list is sorted by service namespace.</p>
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct GetOrganizationsAccessReportFluentBuilder {
    handle: ::std::sync::Arc<crate::client::Handle>,
    inner: crate::operation::get_organizations_access_report::builders::GetOrganizationsAccessReportInputBuilder,
    config_override: ::std::option::Option<crate::config::Builder>,
}
impl
    crate::client::customize::internal::CustomizableSend<
        crate::operation::get_organizations_access_report::GetOrganizationsAccessReportOutput,
        crate::operation::get_organizations_access_report::GetOrganizationsAccessReportError,
    > for GetOrganizationsAccessReportFluentBuilder
{
    fn send(
        self,
        config_override: crate::config::Builder,
    ) -> crate::client::customize::internal::BoxFuture<
        crate::client::customize::internal::SendResult<
            crate::operation::get_organizations_access_report::GetOrganizationsAccessReportOutput,
            crate::operation::get_organizations_access_report::GetOrganizationsAccessReportError,
        >,
    > {
        ::std::boxed::Box::pin(async move { self.config_override(config_override).send().await })
    }
}
impl GetOrganizationsAccessReportFluentBuilder {
    /// Creates a new `GetOrganizationsAccessReportFluentBuilder`.
    pub(crate) fn new(handle: ::std::sync::Arc<crate::client::Handle>) -> Self {
        Self {
            handle,
            inner: ::std::default::Default::default(),
            config_override: ::std::option::Option::None,
        }
    }
    /// Access the GetOrganizationsAccessReport as a reference.
    pub fn as_input(&self) -> &crate::operation::get_organizations_access_report::builders::GetOrganizationsAccessReportInputBuilder {
        &self.inner
    }
    /// Sends the request and returns the response.
    ///
    /// If an error occurs, an `SdkError` will be returned with additional details that
    /// can be matched against.
    ///
    /// By default, any retryable failures will be retried twice. Retry behavior
    /// is configurable with the [RetryConfig](aws_smithy_types::retry::RetryConfig), which can be
    /// set when configuring the client.
    pub async fn send(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_organizations_access_report::GetOrganizationsAccessReportOutput,
        ::aws_smithy_runtime_api::client::result::SdkError<
            crate::operation::get_organizations_access_report::GetOrganizationsAccessReportError,
            ::aws_smithy_runtime_api::client::orchestrator::HttpResponse,
        >,
    > {
        let input = self
            .inner
            .build()
            .map_err(::aws_smithy_runtime_api::client::result::SdkError::construction_failure)?;
        let runtime_plugins = crate::operation::get_organizations_access_report::GetOrganizationsAccessReport::operation_runtime_plugins(
            self.handle.runtime_plugins.clone(),
            &self.handle.conf,
            self.config_override,
        );
        crate::operation::get_organizations_access_report::GetOrganizationsAccessReport::orchestrate(&runtime_plugins, input).await
    }

    /// Consumes this builder, creating a customizable operation that can be modified before being sent.
    pub fn customize(
        self,
    ) -> crate::client::customize::CustomizableOperation<
        crate::operation::get_organizations_access_report::GetOrganizationsAccessReportOutput,
        crate::operation::get_organizations_access_report::GetOrganizationsAccessReportError,
        Self,
    > {
        crate::client::customize::CustomizableOperation::new(self)
    }
    pub(crate) fn config_override(mut self, config_override: impl ::std::convert::Into<crate::config::Builder>) -> Self {
        self.set_config_override(::std::option::Option::Some(config_override.into()));
        self
    }

    pub(crate) fn set_config_override(&mut self, config_override: ::std::option::Option<crate::config::Builder>) -> &mut Self {
        self.config_override = config_override;
        self
    }
    /// <p>The identifier of the request generated by the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateOrganizationsAccessReport.html">GenerateOrganizationsAccessReport</a> operation.</p>
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.job_id(input.into());
        self
    }
    /// <p>The identifier of the request generated by the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateOrganizationsAccessReport.html">GenerateOrganizationsAccessReport</a> operation.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_job_id(input);
        self
    }
    /// <p>The identifier of the request generated by the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateOrganizationsAccessReport.html">GenerateOrganizationsAccessReport</a> operation.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_job_id()
    }
    /// <p>Use this only when paginating results to indicate the maximum number of items you want in the response. If additional items exist beyond the maximum you specify, the <code>IsTruncated</code> response element is <code>true</code>.</p>
    /// <p>If you do not include this parameter, the number of items defaults to 100. Note that IAM might return fewer results, even when there are more results available. In that case, the <code>IsTruncated</code> response element returns <code>true</code>, and <code>Marker</code> contains a value to include in the subsequent call that tells the service where to continue from.</p>
    pub fn max_items(mut self, input: i32) -> Self {
        self.inner = self.inner.max_items(input);
        self
    }
    /// <p>Use this only when paginating results to indicate the maximum number of items you want in the response. If additional items exist beyond the maximum you specify, the <code>IsTruncated</code> response element is <code>true</code>.</p>
    /// <p>If you do not include this parameter, the number of items defaults to 100. Note that IAM might return fewer results, even when there are more results available. In that case, the <code>IsTruncated</code> response element returns <code>true</code>, and <code>Marker</code> contains a value to include in the subsequent call that tells the service where to continue from.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.inner = self.inner.set_max_items(input);
        self
    }
    /// <p>Use this only when paginating results to indicate the maximum number of items you want in the response. If additional items exist beyond the maximum you specify, the <code>IsTruncated</code> response element is <code>true</code>.</p>
    /// <p>If you do not include this parameter, the number of items defaults to 100. Note that IAM might return fewer results, even when there are more results available. In that case, the <code>IsTruncated</code> response element returns <code>true</code>, and <code>Marker</code> contains a value to include in the subsequent call that tells the service where to continue from.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        self.inner.get_max_items()
    }
    /// <p>Use this parameter only when paginating results and only after you receive a response indicating that the results are truncated. Set it to the value of the <code>Marker</code> element in the response that you received to indicate where the next call should start.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inner = self.inner.marker(input.into());
        self
    }
    /// <p>Use this parameter only when paginating results and only after you receive a response indicating that the results are truncated. Set it to the value of the <code>Marker</code> element in the response that you received to indicate where the next call should start.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inner = self.inner.set_marker(input);
        self
    }
    /// <p>Use this parameter only when paginating results and only after you receive a response indicating that the results are truncated. Set it to the value of the <code>Marker</code> element in the response that you received to indicate where the next call should start.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        self.inner.get_marker()
    }
    /// <p>The key that is used to sort the results. If you choose the namespace key, the results are returned in alphabetical order. If you choose the time key, the results are sorted numerically by the date and time.</p>
    pub fn sort_key(mut self, input: crate::types::SortKeyType) -> Self {
        self.inner = self.inner.sort_key(input);
        self
    }
    /// <p>The key that is used to sort the results. If you choose the namespace key, the results are returned in alphabetical order. If you choose the time key, the results are sorted numerically by the date and time.</p>
    pub fn set_sort_key(mut self, input: ::std::option::Option<crate::types::SortKeyType>) -> Self {
        self.inner = self.inner.set_sort_key(input);
        self
    }
    /// <p>The key that is used to sort the results. If you choose the namespace key, the results are returned in alphabetical order. If you choose the time key, the results are sorted numerically by the date and time.</p>
    pub fn get_sort_key(&self) -> &::std::option::Option<crate::types::SortKeyType> {
        self.inner.get_sort_key()
    }
}
