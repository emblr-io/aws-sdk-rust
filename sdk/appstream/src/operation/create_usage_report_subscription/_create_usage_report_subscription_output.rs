// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateUsageReportSubscriptionOutput {
    /// <p>The Amazon S3 bucket where generated reports are stored.</p>
    /// <p>If you enabled on-instance session scripts and Amazon S3 logging for your session script configuration, AppStream 2.0 created an S3 bucket to store the script output. The bucket is unique to your account and Region. When you enable usage reporting in this case, AppStream 2.0 uses the same bucket to store your usage reports. If you haven't already enabled on-instance session scripts, when you enable usage reports, AppStream 2.0 creates a new S3 bucket.</p>
    pub s3_bucket_name: ::std::option::Option<::std::string::String>,
    /// <p>The schedule for generating usage reports.</p>
    pub schedule: ::std::option::Option<crate::types::UsageReportSchedule>,
    _request_id: Option<String>,
}
impl CreateUsageReportSubscriptionOutput {
    /// <p>The Amazon S3 bucket where generated reports are stored.</p>
    /// <p>If you enabled on-instance session scripts and Amazon S3 logging for your session script configuration, AppStream 2.0 created an S3 bucket to store the script output. The bucket is unique to your account and Region. When you enable usage reporting in this case, AppStream 2.0 uses the same bucket to store your usage reports. If you haven't already enabled on-instance session scripts, when you enable usage reports, AppStream 2.0 creates a new S3 bucket.</p>
    pub fn s3_bucket_name(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_name.as_deref()
    }
    /// <p>The schedule for generating usage reports.</p>
    pub fn schedule(&self) -> ::std::option::Option<&crate::types::UsageReportSchedule> {
        self.schedule.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateUsageReportSubscriptionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateUsageReportSubscriptionOutput {
    /// Creates a new builder-style object to manufacture [`CreateUsageReportSubscriptionOutput`](crate::operation::create_usage_report_subscription::CreateUsageReportSubscriptionOutput).
    pub fn builder() -> crate::operation::create_usage_report_subscription::builders::CreateUsageReportSubscriptionOutputBuilder {
        crate::operation::create_usage_report_subscription::builders::CreateUsageReportSubscriptionOutputBuilder::default()
    }
}

/// A builder for [`CreateUsageReportSubscriptionOutput`](crate::operation::create_usage_report_subscription::CreateUsageReportSubscriptionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateUsageReportSubscriptionOutputBuilder {
    pub(crate) s3_bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) schedule: ::std::option::Option<crate::types::UsageReportSchedule>,
    _request_id: Option<String>,
}
impl CreateUsageReportSubscriptionOutputBuilder {
    /// <p>The Amazon S3 bucket where generated reports are stored.</p>
    /// <p>If you enabled on-instance session scripts and Amazon S3 logging for your session script configuration, AppStream 2.0 created an S3 bucket to store the script output. The bucket is unique to your account and Region. When you enable usage reporting in this case, AppStream 2.0 uses the same bucket to store your usage reports. If you haven't already enabled on-instance session scripts, when you enable usage reports, AppStream 2.0 creates a new S3 bucket.</p>
    pub fn s3_bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 bucket where generated reports are stored.</p>
    /// <p>If you enabled on-instance session scripts and Amazon S3 logging for your session script configuration, AppStream 2.0 created an S3 bucket to store the script output. The bucket is unique to your account and Region. When you enable usage reporting in this case, AppStream 2.0 uses the same bucket to store your usage reports. If you haven't already enabled on-instance session scripts, when you enable usage reports, AppStream 2.0 creates a new S3 bucket.</p>
    pub fn set_s3_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_name = input;
        self
    }
    /// <p>The Amazon S3 bucket where generated reports are stored.</p>
    /// <p>If you enabled on-instance session scripts and Amazon S3 logging for your session script configuration, AppStream 2.0 created an S3 bucket to store the script output. The bucket is unique to your account and Region. When you enable usage reporting in this case, AppStream 2.0 uses the same bucket to store your usage reports. If you haven't already enabled on-instance session scripts, when you enable usage reports, AppStream 2.0 creates a new S3 bucket.</p>
    pub fn get_s3_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_name
    }
    /// <p>The schedule for generating usage reports.</p>
    pub fn schedule(mut self, input: crate::types::UsageReportSchedule) -> Self {
        self.schedule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The schedule for generating usage reports.</p>
    pub fn set_schedule(mut self, input: ::std::option::Option<crate::types::UsageReportSchedule>) -> Self {
        self.schedule = input;
        self
    }
    /// <p>The schedule for generating usage reports.</p>
    pub fn get_schedule(&self) -> &::std::option::Option<crate::types::UsageReportSchedule> {
        &self.schedule
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateUsageReportSubscriptionOutput`](crate::operation::create_usage_report_subscription::CreateUsageReportSubscriptionOutput).
    pub fn build(self) -> crate::operation::create_usage_report_subscription::CreateUsageReportSubscriptionOutput {
        crate::operation::create_usage_report_subscription::CreateUsageReportSubscriptionOutput {
            s3_bucket_name: self.s3_bucket_name,
            schedule: self.schedule,
            _request_id: self._request_id,
        }
    }
}
