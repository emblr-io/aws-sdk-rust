// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about the state of the domain relative to the latest service software.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails {
    /// <p>The epoch time when the deployment window closes for required updates. After this time, OpenSearch Service schedules the software upgrade automatically.</p>
    pub automated_update_date: ::std::option::Option<::std::string::String>,
    /// <p>Whether a request to update the domain can be canceled.</p>
    pub cancellable: ::std::option::Option<bool>,
    /// <p>The version of the service software that is currently installed on the domain.</p>
    pub current_version: ::std::option::Option<::std::string::String>,
    /// <p>A more detailed description of the service software status.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The most recent version of the service software.</p>
    pub new_version: ::std::option::Option<::std::string::String>,
    /// <p>Whether a service software update is available for the domain.</p>
    pub update_available: ::std::option::Option<bool>,
    /// <p>The status of the service software update. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLETED</code></p></li>
    /// <li>
    /// <p><code>ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code></p></li>
    /// <li>
    /// <p><code>NOT_ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>PENDING_UPDATE</code></p></li>
    /// </ul>
    pub update_status: ::std::option::Option<::std::string::String>,
    /// <p>Whether the service software update is optional.</p>
    pub optional_deployment: ::std::option::Option<bool>,
}
impl AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails {
    /// <p>The epoch time when the deployment window closes for required updates. After this time, OpenSearch Service schedules the software upgrade automatically.</p>
    pub fn automated_update_date(&self) -> ::std::option::Option<&str> {
        self.automated_update_date.as_deref()
    }
    /// <p>Whether a request to update the domain can be canceled.</p>
    pub fn cancellable(&self) -> ::std::option::Option<bool> {
        self.cancellable
    }
    /// <p>The version of the service software that is currently installed on the domain.</p>
    pub fn current_version(&self) -> ::std::option::Option<&str> {
        self.current_version.as_deref()
    }
    /// <p>A more detailed description of the service software status.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The most recent version of the service software.</p>
    pub fn new_version(&self) -> ::std::option::Option<&str> {
        self.new_version.as_deref()
    }
    /// <p>Whether a service software update is available for the domain.</p>
    pub fn update_available(&self) -> ::std::option::Option<bool> {
        self.update_available
    }
    /// <p>The status of the service software update. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLETED</code></p></li>
    /// <li>
    /// <p><code>ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code></p></li>
    /// <li>
    /// <p><code>NOT_ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>PENDING_UPDATE</code></p></li>
    /// </ul>
    pub fn update_status(&self) -> ::std::option::Option<&str> {
        self.update_status.as_deref()
    }
    /// <p>Whether the service software update is optional.</p>
    pub fn optional_deployment(&self) -> ::std::option::Option<bool> {
        self.optional_deployment
    }
}
impl AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails {
    /// Creates a new builder-style object to manufacture [`AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails`](crate::types::AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails).
    pub fn builder() -> crate::types::builders::AwsOpenSearchServiceDomainServiceSoftwareOptionsDetailsBuilder {
        crate::types::builders::AwsOpenSearchServiceDomainServiceSoftwareOptionsDetailsBuilder::default()
    }
}

/// A builder for [`AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails`](crate::types::AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsOpenSearchServiceDomainServiceSoftwareOptionsDetailsBuilder {
    pub(crate) automated_update_date: ::std::option::Option<::std::string::String>,
    pub(crate) cancellable: ::std::option::Option<bool>,
    pub(crate) current_version: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) new_version: ::std::option::Option<::std::string::String>,
    pub(crate) update_available: ::std::option::Option<bool>,
    pub(crate) update_status: ::std::option::Option<::std::string::String>,
    pub(crate) optional_deployment: ::std::option::Option<bool>,
}
impl AwsOpenSearchServiceDomainServiceSoftwareOptionsDetailsBuilder {
    /// <p>The epoch time when the deployment window closes for required updates. After this time, OpenSearch Service schedules the software upgrade automatically.</p>
    pub fn automated_update_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.automated_update_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The epoch time when the deployment window closes for required updates. After this time, OpenSearch Service schedules the software upgrade automatically.</p>
    pub fn set_automated_update_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.automated_update_date = input;
        self
    }
    /// <p>The epoch time when the deployment window closes for required updates. After this time, OpenSearch Service schedules the software upgrade automatically.</p>
    pub fn get_automated_update_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.automated_update_date
    }
    /// <p>Whether a request to update the domain can be canceled.</p>
    pub fn cancellable(mut self, input: bool) -> Self {
        self.cancellable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether a request to update the domain can be canceled.</p>
    pub fn set_cancellable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.cancellable = input;
        self
    }
    /// <p>Whether a request to update the domain can be canceled.</p>
    pub fn get_cancellable(&self) -> &::std::option::Option<bool> {
        &self.cancellable
    }
    /// <p>The version of the service software that is currently installed on the domain.</p>
    pub fn current_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.current_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the service software that is currently installed on the domain.</p>
    pub fn set_current_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.current_version = input;
        self
    }
    /// <p>The version of the service software that is currently installed on the domain.</p>
    pub fn get_current_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.current_version
    }
    /// <p>A more detailed description of the service software status.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A more detailed description of the service software status.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A more detailed description of the service software status.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The most recent version of the service software.</p>
    pub fn new_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The most recent version of the service software.</p>
    pub fn set_new_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_version = input;
        self
    }
    /// <p>The most recent version of the service software.</p>
    pub fn get_new_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_version
    }
    /// <p>Whether a service software update is available for the domain.</p>
    pub fn update_available(mut self, input: bool) -> Self {
        self.update_available = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether a service software update is available for the domain.</p>
    pub fn set_update_available(mut self, input: ::std::option::Option<bool>) -> Self {
        self.update_available = input;
        self
    }
    /// <p>Whether a service software update is available for the domain.</p>
    pub fn get_update_available(&self) -> &::std::option::Option<bool> {
        &self.update_available
    }
    /// <p>The status of the service software update. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLETED</code></p></li>
    /// <li>
    /// <p><code>ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code></p></li>
    /// <li>
    /// <p><code>NOT_ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>PENDING_UPDATE</code></p></li>
    /// </ul>
    pub fn update_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.update_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the service software update. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLETED</code></p></li>
    /// <li>
    /// <p><code>ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code></p></li>
    /// <li>
    /// <p><code>NOT_ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>PENDING_UPDATE</code></p></li>
    /// </ul>
    pub fn set_update_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.update_status = input;
        self
    }
    /// <p>The status of the service software update. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLETED</code></p></li>
    /// <li>
    /// <p><code>ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code></p></li>
    /// <li>
    /// <p><code>NOT_ELIGIBLE</code></p></li>
    /// <li>
    /// <p><code>PENDING_UPDATE</code></p></li>
    /// </ul>
    pub fn get_update_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.update_status
    }
    /// <p>Whether the service software update is optional.</p>
    pub fn optional_deployment(mut self, input: bool) -> Self {
        self.optional_deployment = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the service software update is optional.</p>
    pub fn set_optional_deployment(mut self, input: ::std::option::Option<bool>) -> Self {
        self.optional_deployment = input;
        self
    }
    /// <p>Whether the service software update is optional.</p>
    pub fn get_optional_deployment(&self) -> &::std::option::Option<bool> {
        &self.optional_deployment
    }
    /// Consumes the builder and constructs a [`AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails`](crate::types::AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails).
    pub fn build(self) -> crate::types::AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails {
        crate::types::AwsOpenSearchServiceDomainServiceSoftwareOptionsDetails {
            automated_update_date: self.automated_update_date,
            cancellable: self.cancellable,
            current_version: self.current_version,
            description: self.description,
            new_version: self.new_version,
            update_available: self.update_available,
            update_status: self.update_status,
            optional_deployment: self.optional_deployment,
        }
    }
}
