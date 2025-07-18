// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents configuration information about a test run, such as the execution timeout (in minutes).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecutionConfiguration {
    /// <p>The number of minutes a test run executes before it times out.</p>
    pub job_timeout_minutes: ::std::option::Option<i32>,
    /// <p>True if account cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub accounts_cleanup: ::std::option::Option<bool>,
    /// <p>True if app package cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub app_packages_cleanup: ::std::option::Option<bool>,
    /// <p>Set to true to enable video capture. Otherwise, set to false. The default is true.</p>
    pub video_capture: ::std::option::Option<bool>,
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information about how Device Farm re-signs your apps, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a> in the <i>AWS Device Farm FAQs</i>.</p>
    pub skip_app_resign: ::std::option::Option<bool>,
}
impl ExecutionConfiguration {
    /// <p>The number of minutes a test run executes before it times out.</p>
    pub fn job_timeout_minutes(&self) -> ::std::option::Option<i32> {
        self.job_timeout_minutes
    }
    /// <p>True if account cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub fn accounts_cleanup(&self) -> ::std::option::Option<bool> {
        self.accounts_cleanup
    }
    /// <p>True if app package cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub fn app_packages_cleanup(&self) -> ::std::option::Option<bool> {
        self.app_packages_cleanup
    }
    /// <p>Set to true to enable video capture. Otherwise, set to false. The default is true.</p>
    pub fn video_capture(&self) -> ::std::option::Option<bool> {
        self.video_capture
    }
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information about how Device Farm re-signs your apps, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a> in the <i>AWS Device Farm FAQs</i>.</p>
    pub fn skip_app_resign(&self) -> ::std::option::Option<bool> {
        self.skip_app_resign
    }
}
impl ExecutionConfiguration {
    /// Creates a new builder-style object to manufacture [`ExecutionConfiguration`](crate::types::ExecutionConfiguration).
    pub fn builder() -> crate::types::builders::ExecutionConfigurationBuilder {
        crate::types::builders::ExecutionConfigurationBuilder::default()
    }
}

/// A builder for [`ExecutionConfiguration`](crate::types::ExecutionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecutionConfigurationBuilder {
    pub(crate) job_timeout_minutes: ::std::option::Option<i32>,
    pub(crate) accounts_cleanup: ::std::option::Option<bool>,
    pub(crate) app_packages_cleanup: ::std::option::Option<bool>,
    pub(crate) video_capture: ::std::option::Option<bool>,
    pub(crate) skip_app_resign: ::std::option::Option<bool>,
}
impl ExecutionConfigurationBuilder {
    /// <p>The number of minutes a test run executes before it times out.</p>
    pub fn job_timeout_minutes(mut self, input: i32) -> Self {
        self.job_timeout_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of minutes a test run executes before it times out.</p>
    pub fn set_job_timeout_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.job_timeout_minutes = input;
        self
    }
    /// <p>The number of minutes a test run executes before it times out.</p>
    pub fn get_job_timeout_minutes(&self) -> &::std::option::Option<i32> {
        &self.job_timeout_minutes
    }
    /// <p>True if account cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub fn accounts_cleanup(mut self, input: bool) -> Self {
        self.accounts_cleanup = ::std::option::Option::Some(input);
        self
    }
    /// <p>True if account cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub fn set_accounts_cleanup(mut self, input: ::std::option::Option<bool>) -> Self {
        self.accounts_cleanup = input;
        self
    }
    /// <p>True if account cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub fn get_accounts_cleanup(&self) -> &::std::option::Option<bool> {
        &self.accounts_cleanup
    }
    /// <p>True if app package cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub fn app_packages_cleanup(mut self, input: bool) -> Self {
        self.app_packages_cleanup = ::std::option::Option::Some(input);
        self
    }
    /// <p>True if app package cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub fn set_app_packages_cleanup(mut self, input: ::std::option::Option<bool>) -> Self {
        self.app_packages_cleanup = input;
        self
    }
    /// <p>True if app package cleanup is enabled at the beginning of the test. Otherwise, false.</p>
    pub fn get_app_packages_cleanup(&self) -> &::std::option::Option<bool> {
        &self.app_packages_cleanup
    }
    /// <p>Set to true to enable video capture. Otherwise, set to false. The default is true.</p>
    pub fn video_capture(mut self, input: bool) -> Self {
        self.video_capture = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set to true to enable video capture. Otherwise, set to false. The default is true.</p>
    pub fn set_video_capture(mut self, input: ::std::option::Option<bool>) -> Self {
        self.video_capture = input;
        self
    }
    /// <p>Set to true to enable video capture. Otherwise, set to false. The default is true.</p>
    pub fn get_video_capture(&self) -> &::std::option::Option<bool> {
        &self.video_capture
    }
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information about how Device Farm re-signs your apps, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a> in the <i>AWS Device Farm FAQs</i>.</p>
    pub fn skip_app_resign(mut self, input: bool) -> Self {
        self.skip_app_resign = ::std::option::Option::Some(input);
        self
    }
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information about how Device Farm re-signs your apps, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a> in the <i>AWS Device Farm FAQs</i>.</p>
    pub fn set_skip_app_resign(mut self, input: ::std::option::Option<bool>) -> Self {
        self.skip_app_resign = input;
        self
    }
    /// <p>When set to <code>true</code>, for private devices, Device Farm does not sign your app again. For public devices, Device Farm always signs your apps again.</p>
    /// <p>For more information about how Device Farm re-signs your apps, see <a href="http://aws.amazon.com/device-farm/faqs/">Do you modify my app?</a> in the <i>AWS Device Farm FAQs</i>.</p>
    pub fn get_skip_app_resign(&self) -> &::std::option::Option<bool> {
        &self.skip_app_resign
    }
    /// Consumes the builder and constructs a [`ExecutionConfiguration`](crate::types::ExecutionConfiguration).
    pub fn build(self) -> crate::types::ExecutionConfiguration {
        crate::types::ExecutionConfiguration {
            job_timeout_minutes: self.job_timeout_minutes,
            accounts_cleanup: self.accounts_cleanup,
            app_packages_cleanup: self.app_packages_cleanup,
            video_capture: self.video_capture,
            skip_app_resign: self.skip_app_resign,
        }
    }
}
