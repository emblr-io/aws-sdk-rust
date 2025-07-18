// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDashboardOutput {
    /// <p>The Amazon Resource Name (ARN) of the dashboard.</p>
    pub dashboard_arn: ::std::option::Option<::std::string::String>,
    /// <p>The detailed information about the dashboard, including what widgets are included and their location on the dashboard. For more information about the <code>DashboardBody</code> syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html">Dashboard Body Structure and Syntax</a>.</p>
    pub dashboard_body: ::std::option::Option<::std::string::String>,
    /// <p>The name of the dashboard.</p>
    pub dashboard_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetDashboardOutput {
    /// <p>The Amazon Resource Name (ARN) of the dashboard.</p>
    pub fn dashboard_arn(&self) -> ::std::option::Option<&str> {
        self.dashboard_arn.as_deref()
    }
    /// <p>The detailed information about the dashboard, including what widgets are included and their location on the dashboard. For more information about the <code>DashboardBody</code> syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html">Dashboard Body Structure and Syntax</a>.</p>
    pub fn dashboard_body(&self) -> ::std::option::Option<&str> {
        self.dashboard_body.as_deref()
    }
    /// <p>The name of the dashboard.</p>
    pub fn dashboard_name(&self) -> ::std::option::Option<&str> {
        self.dashboard_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetDashboardOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDashboardOutput {
    /// Creates a new builder-style object to manufacture [`GetDashboardOutput`](crate::operation::get_dashboard::GetDashboardOutput).
    pub fn builder() -> crate::operation::get_dashboard::builders::GetDashboardOutputBuilder {
        crate::operation::get_dashboard::builders::GetDashboardOutputBuilder::default()
    }
}

/// A builder for [`GetDashboardOutput`](crate::operation::get_dashboard::GetDashboardOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDashboardOutputBuilder {
    pub(crate) dashboard_arn: ::std::option::Option<::std::string::String>,
    pub(crate) dashboard_body: ::std::option::Option<::std::string::String>,
    pub(crate) dashboard_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetDashboardOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the dashboard.</p>
    pub fn dashboard_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dashboard_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dashboard.</p>
    pub fn set_dashboard_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dashboard_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dashboard.</p>
    pub fn get_dashboard_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dashboard_arn
    }
    /// <p>The detailed information about the dashboard, including what widgets are included and their location on the dashboard. For more information about the <code>DashboardBody</code> syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html">Dashboard Body Structure and Syntax</a>.</p>
    pub fn dashboard_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dashboard_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The detailed information about the dashboard, including what widgets are included and their location on the dashboard. For more information about the <code>DashboardBody</code> syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html">Dashboard Body Structure and Syntax</a>.</p>
    pub fn set_dashboard_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dashboard_body = input;
        self
    }
    /// <p>The detailed information about the dashboard, including what widgets are included and their location on the dashboard. For more information about the <code>DashboardBody</code> syntax, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CloudWatch-Dashboard-Body-Structure.html">Dashboard Body Structure and Syntax</a>.</p>
    pub fn get_dashboard_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.dashboard_body
    }
    /// <p>The name of the dashboard.</p>
    pub fn dashboard_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dashboard_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the dashboard.</p>
    pub fn set_dashboard_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dashboard_name = input;
        self
    }
    /// <p>The name of the dashboard.</p>
    pub fn get_dashboard_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.dashboard_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDashboardOutput`](crate::operation::get_dashboard::GetDashboardOutput).
    pub fn build(self) -> crate::operation::get_dashboard::GetDashboardOutput {
        crate::operation::get_dashboard::GetDashboardOutput {
            dashboard_arn: self.dashboard_arn,
            dashboard_body: self.dashboard_body,
            dashboard_name: self.dashboard_name,
            _request_id: self._request_id,
        }
    }
}
