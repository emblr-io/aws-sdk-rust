// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// DVB Service Description Table (SDT)
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DvbSdtSettings {
    /// Selects method of inserting SDT information into output stream. The sdtFollow setting copies SDT information from input stream to output stream. The sdtFollowIfPresent setting copies SDT information from input stream to output stream if SDT information is present in the input, otherwise it will fall back on the user-defined values. The sdtManual setting means user will enter the SDT information. The sdtNone setting means output stream will not contain SDT information.
    pub output_sdt: ::std::option::Option<crate::types::DvbSdtOutputSdt>,
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub rep_interval: ::std::option::Option<i32>,
    /// The service name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub service_name: ::std::option::Option<::std::string::String>,
    /// The service provider name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub service_provider_name: ::std::option::Option<::std::string::String>,
}
impl DvbSdtSettings {
    /// Selects method of inserting SDT information into output stream. The sdtFollow setting copies SDT information from input stream to output stream. The sdtFollowIfPresent setting copies SDT information from input stream to output stream if SDT information is present in the input, otherwise it will fall back on the user-defined values. The sdtManual setting means user will enter the SDT information. The sdtNone setting means output stream will not contain SDT information.
    pub fn output_sdt(&self) -> ::std::option::Option<&crate::types::DvbSdtOutputSdt> {
        self.output_sdt.as_ref()
    }
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub fn rep_interval(&self) -> ::std::option::Option<i32> {
        self.rep_interval
    }
    /// The service name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub fn service_name(&self) -> ::std::option::Option<&str> {
        self.service_name.as_deref()
    }
    /// The service provider name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub fn service_provider_name(&self) -> ::std::option::Option<&str> {
        self.service_provider_name.as_deref()
    }
}
impl DvbSdtSettings {
    /// Creates a new builder-style object to manufacture [`DvbSdtSettings`](crate::types::DvbSdtSettings).
    pub fn builder() -> crate::types::builders::DvbSdtSettingsBuilder {
        crate::types::builders::DvbSdtSettingsBuilder::default()
    }
}

/// A builder for [`DvbSdtSettings`](crate::types::DvbSdtSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DvbSdtSettingsBuilder {
    pub(crate) output_sdt: ::std::option::Option<crate::types::DvbSdtOutputSdt>,
    pub(crate) rep_interval: ::std::option::Option<i32>,
    pub(crate) service_name: ::std::option::Option<::std::string::String>,
    pub(crate) service_provider_name: ::std::option::Option<::std::string::String>,
}
impl DvbSdtSettingsBuilder {
    /// Selects method of inserting SDT information into output stream. The sdtFollow setting copies SDT information from input stream to output stream. The sdtFollowIfPresent setting copies SDT information from input stream to output stream if SDT information is present in the input, otherwise it will fall back on the user-defined values. The sdtManual setting means user will enter the SDT information. The sdtNone setting means output stream will not contain SDT information.
    pub fn output_sdt(mut self, input: crate::types::DvbSdtOutputSdt) -> Self {
        self.output_sdt = ::std::option::Option::Some(input);
        self
    }
    /// Selects method of inserting SDT information into output stream. The sdtFollow setting copies SDT information from input stream to output stream. The sdtFollowIfPresent setting copies SDT information from input stream to output stream if SDT information is present in the input, otherwise it will fall back on the user-defined values. The sdtManual setting means user will enter the SDT information. The sdtNone setting means output stream will not contain SDT information.
    pub fn set_output_sdt(mut self, input: ::std::option::Option<crate::types::DvbSdtOutputSdt>) -> Self {
        self.output_sdt = input;
        self
    }
    /// Selects method of inserting SDT information into output stream. The sdtFollow setting copies SDT information from input stream to output stream. The sdtFollowIfPresent setting copies SDT information from input stream to output stream if SDT information is present in the input, otherwise it will fall back on the user-defined values. The sdtManual setting means user will enter the SDT information. The sdtNone setting means output stream will not contain SDT information.
    pub fn get_output_sdt(&self) -> &::std::option::Option<crate::types::DvbSdtOutputSdt> {
        &self.output_sdt
    }
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub fn rep_interval(mut self, input: i32) -> Self {
        self.rep_interval = ::std::option::Option::Some(input);
        self
    }
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub fn set_rep_interval(mut self, input: ::std::option::Option<i32>) -> Self {
        self.rep_interval = input;
        self
    }
    /// The number of milliseconds between instances of this table in the output transport stream.
    pub fn get_rep_interval(&self) -> &::std::option::Option<i32> {
        &self.rep_interval
    }
    /// The service name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub fn service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// The service name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub fn set_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_name = input;
        self
    }
    /// The service name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub fn get_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_name
    }
    /// The service provider name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub fn service_provider_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_provider_name = ::std::option::Option::Some(input.into());
        self
    }
    /// The service provider name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub fn set_service_provider_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_provider_name = input;
        self
    }
    /// The service provider name placed in the serviceDescriptor in the Service Description Table. Maximum length is 256 characters.
    pub fn get_service_provider_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_provider_name
    }
    /// Consumes the builder and constructs a [`DvbSdtSettings`](crate::types::DvbSdtSettings).
    pub fn build(self) -> crate::types::DvbSdtSettings {
        crate::types::DvbSdtSettings {
            output_sdt: self.output_sdt,
            rep_interval: self.rep_interval,
            service_name: self.service_name,
            service_provider_name: self.service_provider_name,
        }
    }
}
