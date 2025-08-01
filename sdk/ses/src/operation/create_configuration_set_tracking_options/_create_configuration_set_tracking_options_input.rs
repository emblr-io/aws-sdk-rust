// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a request to create an open and click tracking option object in a configuration set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateConfigurationSetTrackingOptionsInput {
    /// <p>The name of the configuration set that the tracking options should be associated with.</p>
    pub configuration_set_name: ::std::option::Option<::std::string::String>,
    /// <p>A domain that is used to redirect email recipients to an Amazon SES-operated domain. This domain captures open and click events generated by Amazon SES emails.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/ses/latest/dg/configure-custom-open-click-domains.html">Configuring Custom Domains to Handle Open and Click Tracking</a> in the <i>Amazon SES Developer Guide</i>.</p>
    pub tracking_options: ::std::option::Option<crate::types::TrackingOptions>,
}
impl CreateConfigurationSetTrackingOptionsInput {
    /// <p>The name of the configuration set that the tracking options should be associated with.</p>
    pub fn configuration_set_name(&self) -> ::std::option::Option<&str> {
        self.configuration_set_name.as_deref()
    }
    /// <p>A domain that is used to redirect email recipients to an Amazon SES-operated domain. This domain captures open and click events generated by Amazon SES emails.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/ses/latest/dg/configure-custom-open-click-domains.html">Configuring Custom Domains to Handle Open and Click Tracking</a> in the <i>Amazon SES Developer Guide</i>.</p>
    pub fn tracking_options(&self) -> ::std::option::Option<&crate::types::TrackingOptions> {
        self.tracking_options.as_ref()
    }
}
impl CreateConfigurationSetTrackingOptionsInput {
    /// Creates a new builder-style object to manufacture [`CreateConfigurationSetTrackingOptionsInput`](crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsInput).
    pub fn builder() -> crate::operation::create_configuration_set_tracking_options::builders::CreateConfigurationSetTrackingOptionsInputBuilder {
        crate::operation::create_configuration_set_tracking_options::builders::CreateConfigurationSetTrackingOptionsInputBuilder::default()
    }
}

/// A builder for [`CreateConfigurationSetTrackingOptionsInput`](crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateConfigurationSetTrackingOptionsInputBuilder {
    pub(crate) configuration_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) tracking_options: ::std::option::Option<crate::types::TrackingOptions>,
}
impl CreateConfigurationSetTrackingOptionsInputBuilder {
    /// <p>The name of the configuration set that the tracking options should be associated with.</p>
    /// This field is required.
    pub fn configuration_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration set that the tracking options should be associated with.</p>
    pub fn set_configuration_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_name = input;
        self
    }
    /// <p>The name of the configuration set that the tracking options should be associated with.</p>
    pub fn get_configuration_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_name
    }
    /// <p>A domain that is used to redirect email recipients to an Amazon SES-operated domain. This domain captures open and click events generated by Amazon SES emails.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/ses/latest/dg/configure-custom-open-click-domains.html">Configuring Custom Domains to Handle Open and Click Tracking</a> in the <i>Amazon SES Developer Guide</i>.</p>
    /// This field is required.
    pub fn tracking_options(mut self, input: crate::types::TrackingOptions) -> Self {
        self.tracking_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>A domain that is used to redirect email recipients to an Amazon SES-operated domain. This domain captures open and click events generated by Amazon SES emails.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/ses/latest/dg/configure-custom-open-click-domains.html">Configuring Custom Domains to Handle Open and Click Tracking</a> in the <i>Amazon SES Developer Guide</i>.</p>
    pub fn set_tracking_options(mut self, input: ::std::option::Option<crate::types::TrackingOptions>) -> Self {
        self.tracking_options = input;
        self
    }
    /// <p>A domain that is used to redirect email recipients to an Amazon SES-operated domain. This domain captures open and click events generated by Amazon SES emails.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/ses/latest/dg/configure-custom-open-click-domains.html">Configuring Custom Domains to Handle Open and Click Tracking</a> in the <i>Amazon SES Developer Guide</i>.</p>
    pub fn get_tracking_options(&self) -> &::std::option::Option<crate::types::TrackingOptions> {
        &self.tracking_options
    }
    /// Consumes the builder and constructs a [`CreateConfigurationSetTrackingOptionsInput`](crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_configuration_set_tracking_options::CreateConfigurationSetTrackingOptionsInput {
                configuration_set_name: self.configuration_set_name,
                tracking_options: self.tracking_options,
            },
        )
    }
}
