// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCampaignCommunicationLimitsOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteCampaignCommunicationLimitsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteCampaignCommunicationLimitsOutput {
    /// Creates a new builder-style object to manufacture [`DeleteCampaignCommunicationLimitsOutput`](crate::operation::delete_campaign_communication_limits::DeleteCampaignCommunicationLimitsOutput).
    pub fn builder() -> crate::operation::delete_campaign_communication_limits::builders::DeleteCampaignCommunicationLimitsOutputBuilder {
        crate::operation::delete_campaign_communication_limits::builders::DeleteCampaignCommunicationLimitsOutputBuilder::default()
    }
}

/// A builder for [`DeleteCampaignCommunicationLimitsOutput`](crate::operation::delete_campaign_communication_limits::DeleteCampaignCommunicationLimitsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCampaignCommunicationLimitsOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteCampaignCommunicationLimitsOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteCampaignCommunicationLimitsOutput`](crate::operation::delete_campaign_communication_limits::DeleteCampaignCommunicationLimitsOutput).
    pub fn build(self) -> crate::operation::delete_campaign_communication_limits::DeleteCampaignCommunicationLimitsOutput {
        crate::operation::delete_campaign_communication_limits::DeleteCampaignCommunicationLimitsOutput {
            _request_id: self._request_id,
        }
    }
}
