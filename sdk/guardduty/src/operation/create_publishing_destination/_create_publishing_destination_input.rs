// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePublishingDestinationInput {
    /// <p>The ID of the GuardDuty detector associated with the publishing destination.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub detector_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of resource for the publishing destination. Currently only Amazon S3 buckets are supported.</p>
    pub destination_type: ::std::option::Option<crate::types::DestinationType>,
    /// <p>The properties of the publishing destination, including the ARNs for the destination and the KMS key used for encryption.</p>
    pub destination_properties: ::std::option::Option<crate::types::DestinationProperties>,
    /// <p>The idempotency token for the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreatePublishingDestinationInput {
    /// <p>The ID of the GuardDuty detector associated with the publishing destination.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub fn detector_id(&self) -> ::std::option::Option<&str> {
        self.detector_id.as_deref()
    }
    /// <p>The type of resource for the publishing destination. Currently only Amazon S3 buckets are supported.</p>
    pub fn destination_type(&self) -> ::std::option::Option<&crate::types::DestinationType> {
        self.destination_type.as_ref()
    }
    /// <p>The properties of the publishing destination, including the ARNs for the destination and the KMS key used for encryption.</p>
    pub fn destination_properties(&self) -> ::std::option::Option<&crate::types::DestinationProperties> {
        self.destination_properties.as_ref()
    }
    /// <p>The idempotency token for the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreatePublishingDestinationInput {
    /// Creates a new builder-style object to manufacture [`CreatePublishingDestinationInput`](crate::operation::create_publishing_destination::CreatePublishingDestinationInput).
    pub fn builder() -> crate::operation::create_publishing_destination::builders::CreatePublishingDestinationInputBuilder {
        crate::operation::create_publishing_destination::builders::CreatePublishingDestinationInputBuilder::default()
    }
}

/// A builder for [`CreatePublishingDestinationInput`](crate::operation::create_publishing_destination::CreatePublishingDestinationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePublishingDestinationInputBuilder {
    pub(crate) detector_id: ::std::option::Option<::std::string::String>,
    pub(crate) destination_type: ::std::option::Option<crate::types::DestinationType>,
    pub(crate) destination_properties: ::std::option::Option<crate::types::DestinationProperties>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreatePublishingDestinationInputBuilder {
    /// <p>The ID of the GuardDuty detector associated with the publishing destination.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    /// This field is required.
    pub fn detector_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detector_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the GuardDuty detector associated with the publishing destination.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub fn set_detector_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detector_id = input;
        self
    }
    /// <p>The ID of the GuardDuty detector associated with the publishing destination.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub fn get_detector_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.detector_id
    }
    /// <p>The type of resource for the publishing destination. Currently only Amazon S3 buckets are supported.</p>
    /// This field is required.
    pub fn destination_type(mut self, input: crate::types::DestinationType) -> Self {
        self.destination_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of resource for the publishing destination. Currently only Amazon S3 buckets are supported.</p>
    pub fn set_destination_type(mut self, input: ::std::option::Option<crate::types::DestinationType>) -> Self {
        self.destination_type = input;
        self
    }
    /// <p>The type of resource for the publishing destination. Currently only Amazon S3 buckets are supported.</p>
    pub fn get_destination_type(&self) -> &::std::option::Option<crate::types::DestinationType> {
        &self.destination_type
    }
    /// <p>The properties of the publishing destination, including the ARNs for the destination and the KMS key used for encryption.</p>
    /// This field is required.
    pub fn destination_properties(mut self, input: crate::types::DestinationProperties) -> Self {
        self.destination_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties of the publishing destination, including the ARNs for the destination and the KMS key used for encryption.</p>
    pub fn set_destination_properties(mut self, input: ::std::option::Option<crate::types::DestinationProperties>) -> Self {
        self.destination_properties = input;
        self
    }
    /// <p>The properties of the publishing destination, including the ARNs for the destination and the KMS key used for encryption.</p>
    pub fn get_destination_properties(&self) -> &::std::option::Option<crate::types::DestinationProperties> {
        &self.destination_properties
    }
    /// <p>The idempotency token for the request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The idempotency token for the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The idempotency token for the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreatePublishingDestinationInput`](crate::operation::create_publishing_destination::CreatePublishingDestinationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_publishing_destination::CreatePublishingDestinationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_publishing_destination::CreatePublishingDestinationInput {
            detector_id: self.detector_id,
            destination_type: self.destination_type,
            destination_properties: self.destination_properties,
            client_token: self.client_token,
        })
    }
}
