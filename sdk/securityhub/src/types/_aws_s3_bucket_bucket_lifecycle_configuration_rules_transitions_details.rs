// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A rule for when objects transition to specific storage classes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails {
    /// <p>A date on which to transition objects to the specified storage class. If you provide <code>Date</code>, you cannot provide <code>Days</code>.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub date: ::std::option::Option<::std::string::String>,
    /// <p>The number of days after which to transition the object to the specified storage class. If you provide <code>Days</code>, you cannot provide <code>Date</code>.</p>
    pub days: ::std::option::Option<i32>,
    /// <p>The storage class to transition the object to. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>DEEP_ARCHIVE</code></p></li>
    /// <li>
    /// <p><code>GLACIER</code></p></li>
    /// <li>
    /// <p><code>INTELLIGENT_TIERING</code></p></li>
    /// <li>
    /// <p><code>ONEZONE_IA</code></p></li>
    /// <li>
    /// <p><code>STANDARD_IA</code></p></li>
    /// </ul>
    pub storage_class: ::std::option::Option<::std::string::String>,
}
impl AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails {
    /// <p>A date on which to transition objects to the specified storage class. If you provide <code>Date</code>, you cannot provide <code>Days</code>.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn date(&self) -> ::std::option::Option<&str> {
        self.date.as_deref()
    }
    /// <p>The number of days after which to transition the object to the specified storage class. If you provide <code>Days</code>, you cannot provide <code>Date</code>.</p>
    pub fn days(&self) -> ::std::option::Option<i32> {
        self.days
    }
    /// <p>The storage class to transition the object to. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>DEEP_ARCHIVE</code></p></li>
    /// <li>
    /// <p><code>GLACIER</code></p></li>
    /// <li>
    /// <p><code>INTELLIGENT_TIERING</code></p></li>
    /// <li>
    /// <p><code>ONEZONE_IA</code></p></li>
    /// <li>
    /// <p><code>STANDARD_IA</code></p></li>
    /// </ul>
    pub fn storage_class(&self) -> ::std::option::Option<&str> {
        self.storage_class.as_deref()
    }
}
impl AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails {
    /// Creates a new builder-style object to manufacture [`AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails`](crate::types::AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails).
    pub fn builder() -> crate::types::builders::AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetailsBuilder {
        crate::types::builders::AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetailsBuilder::default()
    }
}

/// A builder for [`AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails`](crate::types::AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetailsBuilder {
    pub(crate) date: ::std::option::Option<::std::string::String>,
    pub(crate) days: ::std::option::Option<i32>,
    pub(crate) storage_class: ::std::option::Option<::std::string::String>,
}
impl AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetailsBuilder {
    /// <p>A date on which to transition objects to the specified storage class. If you provide <code>Date</code>, you cannot provide <code>Days</code>.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A date on which to transition objects to the specified storage class. If you provide <code>Date</code>, you cannot provide <code>Days</code>.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn set_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.date = input;
        self
    }
    /// <p>A date on which to transition objects to the specified storage class. If you provide <code>Date</code>, you cannot provide <code>Days</code>.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn get_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.date
    }
    /// <p>The number of days after which to transition the object to the specified storage class. If you provide <code>Days</code>, you cannot provide <code>Date</code>.</p>
    pub fn days(mut self, input: i32) -> Self {
        self.days = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of days after which to transition the object to the specified storage class. If you provide <code>Days</code>, you cannot provide <code>Date</code>.</p>
    pub fn set_days(mut self, input: ::std::option::Option<i32>) -> Self {
        self.days = input;
        self
    }
    /// <p>The number of days after which to transition the object to the specified storage class. If you provide <code>Days</code>, you cannot provide <code>Date</code>.</p>
    pub fn get_days(&self) -> &::std::option::Option<i32> {
        &self.days
    }
    /// <p>The storage class to transition the object to. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>DEEP_ARCHIVE</code></p></li>
    /// <li>
    /// <p><code>GLACIER</code></p></li>
    /// <li>
    /// <p><code>INTELLIGENT_TIERING</code></p></li>
    /// <li>
    /// <p><code>ONEZONE_IA</code></p></li>
    /// <li>
    /// <p><code>STANDARD_IA</code></p></li>
    /// </ul>
    pub fn storage_class(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.storage_class = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The storage class to transition the object to. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>DEEP_ARCHIVE</code></p></li>
    /// <li>
    /// <p><code>GLACIER</code></p></li>
    /// <li>
    /// <p><code>INTELLIGENT_TIERING</code></p></li>
    /// <li>
    /// <p><code>ONEZONE_IA</code></p></li>
    /// <li>
    /// <p><code>STANDARD_IA</code></p></li>
    /// </ul>
    pub fn set_storage_class(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.storage_class = input;
        self
    }
    /// <p>The storage class to transition the object to. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>DEEP_ARCHIVE</code></p></li>
    /// <li>
    /// <p><code>GLACIER</code></p></li>
    /// <li>
    /// <p><code>INTELLIGENT_TIERING</code></p></li>
    /// <li>
    /// <p><code>ONEZONE_IA</code></p></li>
    /// <li>
    /// <p><code>STANDARD_IA</code></p></li>
    /// </ul>
    pub fn get_storage_class(&self) -> &::std::option::Option<::std::string::String> {
        &self.storage_class
    }
    /// Consumes the builder and constructs a [`AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails`](crate::types::AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails).
    pub fn build(self) -> crate::types::AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails {
        crate::types::AwsS3BucketBucketLifecycleConfigurationRulesTransitionsDetails {
            date: self.date,
            days: self.days,
            storage_class: self.storage_class,
        }
    }
}
