// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateCampaignOutput {
    /// <p>The Amazon Resource Name (ARN) of the campaign.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the updated campaign.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The state of a campaign. The status can be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code> - Amazon Web Services IoT FleetWise is processing your request to create the campaign.</p></li>
    /// <li>
    /// <p><code>WAITING_FOR_APPROVAL</code> - After you create a campaign, it enters this state. Use the API operation to approve the campaign for deployment to the target vehicle or fleet.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> - The campaign is active.</p></li>
    /// <li>
    /// <p><code>SUSPENDED</code> - The campaign is suspended. To resume the campaign, use the API operation.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::CampaignStatus>,
    _request_id: Option<String>,
}
impl UpdateCampaignOutput {
    /// <p>The Amazon Resource Name (ARN) of the campaign.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the updated campaign.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The state of a campaign. The status can be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code> - Amazon Web Services IoT FleetWise is processing your request to create the campaign.</p></li>
    /// <li>
    /// <p><code>WAITING_FOR_APPROVAL</code> - After you create a campaign, it enters this state. Use the API operation to approve the campaign for deployment to the target vehicle or fleet.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> - The campaign is active.</p></li>
    /// <li>
    /// <p><code>SUSPENDED</code> - The campaign is suspended. To resume the campaign, use the API operation.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::CampaignStatus> {
        self.status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateCampaignOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateCampaignOutput {
    /// Creates a new builder-style object to manufacture [`UpdateCampaignOutput`](crate::operation::update_campaign::UpdateCampaignOutput).
    pub fn builder() -> crate::operation::update_campaign::builders::UpdateCampaignOutputBuilder {
        crate::operation::update_campaign::builders::UpdateCampaignOutputBuilder::default()
    }
}

/// A builder for [`UpdateCampaignOutput`](crate::operation::update_campaign::UpdateCampaignOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateCampaignOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::CampaignStatus>,
    _request_id: Option<String>,
}
impl UpdateCampaignOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the campaign.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the campaign.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the campaign.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the updated campaign.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the updated campaign.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the updated campaign.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The state of a campaign. The status can be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code> - Amazon Web Services IoT FleetWise is processing your request to create the campaign.</p></li>
    /// <li>
    /// <p><code>WAITING_FOR_APPROVAL</code> - After you create a campaign, it enters this state. Use the API operation to approve the campaign for deployment to the target vehicle or fleet.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> - The campaign is active.</p></li>
    /// <li>
    /// <p><code>SUSPENDED</code> - The campaign is suspended. To resume the campaign, use the API operation.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::CampaignStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of a campaign. The status can be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code> - Amazon Web Services IoT FleetWise is processing your request to create the campaign.</p></li>
    /// <li>
    /// <p><code>WAITING_FOR_APPROVAL</code> - After you create a campaign, it enters this state. Use the API operation to approve the campaign for deployment to the target vehicle or fleet.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> - The campaign is active.</p></li>
    /// <li>
    /// <p><code>SUSPENDED</code> - The campaign is suspended. To resume the campaign, use the API operation.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::CampaignStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The state of a campaign. The status can be one of:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING</code> - Amazon Web Services IoT FleetWise is processing your request to create the campaign.</p></li>
    /// <li>
    /// <p><code>WAITING_FOR_APPROVAL</code> - After you create a campaign, it enters this state. Use the API operation to approve the campaign for deployment to the target vehicle or fleet.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> - The campaign is active.</p></li>
    /// <li>
    /// <p><code>SUSPENDED</code> - The campaign is suspended. To resume the campaign, use the API operation.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::CampaignStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateCampaignOutput`](crate::operation::update_campaign::UpdateCampaignOutput).
    pub fn build(self) -> crate::operation::update_campaign::UpdateCampaignOutput {
        crate::operation::update_campaign::UpdateCampaignOutput {
            arn: self.arn,
            name: self.name,
            status: self.status,
            _request_id: self._request_id,
        }
    }
}
