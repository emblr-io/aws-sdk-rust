// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon S3 result from the snapshot job. The result includes the <code>DestinationConfiguration</code> and the Amazon S3 Uri. If an error occured during the job, the result returns information on the error.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SnapshotJobS3Result {
    /// <p>A list of Amazon S3 bucket configurations that are provided when you make a <code>StartDashboardSnapshotJob</code> API call.</p>
    pub s3_destination_configuration: ::std::option::Option<crate::types::SnapshotS3DestinationConfiguration>,
    /// <p>The Amazon S3 Uri.</p>
    pub s3_uri: ::std::option::Option<::std::string::String>,
    /// <p>An array of error records that describe any failures that occur while the dashboard snapshot job runs.</p>
    pub error_info: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotJobResultErrorInfo>>,
}
impl SnapshotJobS3Result {
    /// <p>A list of Amazon S3 bucket configurations that are provided when you make a <code>StartDashboardSnapshotJob</code> API call.</p>
    pub fn s3_destination_configuration(&self) -> ::std::option::Option<&crate::types::SnapshotS3DestinationConfiguration> {
        self.s3_destination_configuration.as_ref()
    }
    /// <p>The Amazon S3 Uri.</p>
    pub fn s3_uri(&self) -> ::std::option::Option<&str> {
        self.s3_uri.as_deref()
    }
    /// <p>An array of error records that describe any failures that occur while the dashboard snapshot job runs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.error_info.is_none()`.
    pub fn error_info(&self) -> &[crate::types::SnapshotJobResultErrorInfo] {
        self.error_info.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for SnapshotJobS3Result {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SnapshotJobS3Result");
        formatter.field("s3_destination_configuration", &self.s3_destination_configuration);
        formatter.field("s3_uri", &"*** Sensitive Data Redacted ***");
        formatter.field("error_info", &self.error_info);
        formatter.finish()
    }
}
impl SnapshotJobS3Result {
    /// Creates a new builder-style object to manufacture [`SnapshotJobS3Result`](crate::types::SnapshotJobS3Result).
    pub fn builder() -> crate::types::builders::SnapshotJobS3ResultBuilder {
        crate::types::builders::SnapshotJobS3ResultBuilder::default()
    }
}

/// A builder for [`SnapshotJobS3Result`](crate::types::SnapshotJobS3Result).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SnapshotJobS3ResultBuilder {
    pub(crate) s3_destination_configuration: ::std::option::Option<crate::types::SnapshotS3DestinationConfiguration>,
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) error_info: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotJobResultErrorInfo>>,
}
impl SnapshotJobS3ResultBuilder {
    /// <p>A list of Amazon S3 bucket configurations that are provided when you make a <code>StartDashboardSnapshotJob</code> API call.</p>
    pub fn s3_destination_configuration(mut self, input: crate::types::SnapshotS3DestinationConfiguration) -> Self {
        self.s3_destination_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of Amazon S3 bucket configurations that are provided when you make a <code>StartDashboardSnapshotJob</code> API call.</p>
    pub fn set_s3_destination_configuration(mut self, input: ::std::option::Option<crate::types::SnapshotS3DestinationConfiguration>) -> Self {
        self.s3_destination_configuration = input;
        self
    }
    /// <p>A list of Amazon S3 bucket configurations that are provided when you make a <code>StartDashboardSnapshotJob</code> API call.</p>
    pub fn get_s3_destination_configuration(&self) -> &::std::option::Option<crate::types::SnapshotS3DestinationConfiguration> {
        &self.s3_destination_configuration
    }
    /// <p>The Amazon S3 Uri.</p>
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 Uri.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>The Amazon S3 Uri.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// Appends an item to `error_info`.
    ///
    /// To override the contents of this collection use [`set_error_info`](Self::set_error_info).
    ///
    /// <p>An array of error records that describe any failures that occur while the dashboard snapshot job runs.</p>
    pub fn error_info(mut self, input: crate::types::SnapshotJobResultErrorInfo) -> Self {
        let mut v = self.error_info.unwrap_or_default();
        v.push(input);
        self.error_info = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of error records that describe any failures that occur while the dashboard snapshot job runs.</p>
    pub fn set_error_info(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SnapshotJobResultErrorInfo>>) -> Self {
        self.error_info = input;
        self
    }
    /// <p>An array of error records that describe any failures that occur while the dashboard snapshot job runs.</p>
    pub fn get_error_info(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SnapshotJobResultErrorInfo>> {
        &self.error_info
    }
    /// Consumes the builder and constructs a [`SnapshotJobS3Result`](crate::types::SnapshotJobS3Result).
    pub fn build(self) -> crate::types::SnapshotJobS3Result {
        crate::types::SnapshotJobS3Result {
            s3_destination_configuration: self.s3_destination_configuration,
            s3_uri: self.s3_uri,
            error_info: self.error_info,
        }
    }
}
impl ::std::fmt::Debug for SnapshotJobS3ResultBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SnapshotJobS3ResultBuilder");
        formatter.field("s3_destination_configuration", &self.s3_destination_configuration);
        formatter.field("s3_uri", &"*** Sensitive Data Redacted ***");
        formatter.field("error_info", &self.error_info);
        formatter.finish()
    }
}
