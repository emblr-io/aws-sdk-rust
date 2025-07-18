// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about an email identity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEmailIdentityOutput {
    /// <p>The email identity type.</p>
    pub identity_type: ::std::option::Option<crate::types::IdentityType>,
    /// <p>The feedback forwarding configuration for the identity.</p>
    /// <p>If the value is <code>true</code>, Amazon Pinpoint sends you email notifications when bounce or complaint events occur. Amazon Pinpoint sends this notification to the address that you specified in the Return-Path header of the original email.</p>
    /// <p>When you set this value to <code>false</code>, Amazon Pinpoint sends notifications through other mechanisms, such as by notifying an Amazon SNS topic or another event destination. You're required to have a method of tracking bounces and complaints. If you haven't set up another mechanism for receiving bounce or complaint notifications, Amazon Pinpoint sends an email notification when these events occur (even if this setting is disabled).</p>
    pub feedback_forwarding_status: bool,
    /// <p>Specifies whether or not the identity is verified. In Amazon Pinpoint, you can only send email from verified email addresses or domains. For more information about verifying identities, see the <a href="https://docs.aws.amazon.com/pinpoint/latest/userguide/channels-email-manage-verify.html">Amazon Pinpoint User Guide</a>.</p>
    pub verified_for_sending_status: bool,
    /// <p>An object that contains information about the DKIM attributes for the identity. This object includes the tokens that you use to create the CNAME records that are required to complete the DKIM verification process.</p>
    pub dkim_attributes: ::std::option::Option<crate::types::DkimAttributes>,
    /// <p>An object that contains information about the Mail-From attributes for the email identity.</p>
    pub mail_from_attributes: ::std::option::Option<crate::types::MailFromAttributes>,
    /// <p>An array of objects that define the tags (keys and values) that are associated with the email identity.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    _request_id: Option<String>,
}
impl GetEmailIdentityOutput {
    /// <p>The email identity type.</p>
    pub fn identity_type(&self) -> ::std::option::Option<&crate::types::IdentityType> {
        self.identity_type.as_ref()
    }
    /// <p>The feedback forwarding configuration for the identity.</p>
    /// <p>If the value is <code>true</code>, Amazon Pinpoint sends you email notifications when bounce or complaint events occur. Amazon Pinpoint sends this notification to the address that you specified in the Return-Path header of the original email.</p>
    /// <p>When you set this value to <code>false</code>, Amazon Pinpoint sends notifications through other mechanisms, such as by notifying an Amazon SNS topic or another event destination. You're required to have a method of tracking bounces and complaints. If you haven't set up another mechanism for receiving bounce or complaint notifications, Amazon Pinpoint sends an email notification when these events occur (even if this setting is disabled).</p>
    pub fn feedback_forwarding_status(&self) -> bool {
        self.feedback_forwarding_status
    }
    /// <p>Specifies whether or not the identity is verified. In Amazon Pinpoint, you can only send email from verified email addresses or domains. For more information about verifying identities, see the <a href="https://docs.aws.amazon.com/pinpoint/latest/userguide/channels-email-manage-verify.html">Amazon Pinpoint User Guide</a>.</p>
    pub fn verified_for_sending_status(&self) -> bool {
        self.verified_for_sending_status
    }
    /// <p>An object that contains information about the DKIM attributes for the identity. This object includes the tokens that you use to create the CNAME records that are required to complete the DKIM verification process.</p>
    pub fn dkim_attributes(&self) -> ::std::option::Option<&crate::types::DkimAttributes> {
        self.dkim_attributes.as_ref()
    }
    /// <p>An object that contains information about the Mail-From attributes for the email identity.</p>
    pub fn mail_from_attributes(&self) -> ::std::option::Option<&crate::types::MailFromAttributes> {
        self.mail_from_attributes.as_ref()
    }
    /// <p>An array of objects that define the tags (keys and values) that are associated with the email identity.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetEmailIdentityOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetEmailIdentityOutput {
    /// Creates a new builder-style object to manufacture [`GetEmailIdentityOutput`](crate::operation::get_email_identity::GetEmailIdentityOutput).
    pub fn builder() -> crate::operation::get_email_identity::builders::GetEmailIdentityOutputBuilder {
        crate::operation::get_email_identity::builders::GetEmailIdentityOutputBuilder::default()
    }
}

/// A builder for [`GetEmailIdentityOutput`](crate::operation::get_email_identity::GetEmailIdentityOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEmailIdentityOutputBuilder {
    pub(crate) identity_type: ::std::option::Option<crate::types::IdentityType>,
    pub(crate) feedback_forwarding_status: ::std::option::Option<bool>,
    pub(crate) verified_for_sending_status: ::std::option::Option<bool>,
    pub(crate) dkim_attributes: ::std::option::Option<crate::types::DkimAttributes>,
    pub(crate) mail_from_attributes: ::std::option::Option<crate::types::MailFromAttributes>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    _request_id: Option<String>,
}
impl GetEmailIdentityOutputBuilder {
    /// <p>The email identity type.</p>
    pub fn identity_type(mut self, input: crate::types::IdentityType) -> Self {
        self.identity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The email identity type.</p>
    pub fn set_identity_type(mut self, input: ::std::option::Option<crate::types::IdentityType>) -> Self {
        self.identity_type = input;
        self
    }
    /// <p>The email identity type.</p>
    pub fn get_identity_type(&self) -> &::std::option::Option<crate::types::IdentityType> {
        &self.identity_type
    }
    /// <p>The feedback forwarding configuration for the identity.</p>
    /// <p>If the value is <code>true</code>, Amazon Pinpoint sends you email notifications when bounce or complaint events occur. Amazon Pinpoint sends this notification to the address that you specified in the Return-Path header of the original email.</p>
    /// <p>When you set this value to <code>false</code>, Amazon Pinpoint sends notifications through other mechanisms, such as by notifying an Amazon SNS topic or another event destination. You're required to have a method of tracking bounces and complaints. If you haven't set up another mechanism for receiving bounce or complaint notifications, Amazon Pinpoint sends an email notification when these events occur (even if this setting is disabled).</p>
    pub fn feedback_forwarding_status(mut self, input: bool) -> Self {
        self.feedback_forwarding_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The feedback forwarding configuration for the identity.</p>
    /// <p>If the value is <code>true</code>, Amazon Pinpoint sends you email notifications when bounce or complaint events occur. Amazon Pinpoint sends this notification to the address that you specified in the Return-Path header of the original email.</p>
    /// <p>When you set this value to <code>false</code>, Amazon Pinpoint sends notifications through other mechanisms, such as by notifying an Amazon SNS topic or another event destination. You're required to have a method of tracking bounces and complaints. If you haven't set up another mechanism for receiving bounce or complaint notifications, Amazon Pinpoint sends an email notification when these events occur (even if this setting is disabled).</p>
    pub fn set_feedback_forwarding_status(mut self, input: ::std::option::Option<bool>) -> Self {
        self.feedback_forwarding_status = input;
        self
    }
    /// <p>The feedback forwarding configuration for the identity.</p>
    /// <p>If the value is <code>true</code>, Amazon Pinpoint sends you email notifications when bounce or complaint events occur. Amazon Pinpoint sends this notification to the address that you specified in the Return-Path header of the original email.</p>
    /// <p>When you set this value to <code>false</code>, Amazon Pinpoint sends notifications through other mechanisms, such as by notifying an Amazon SNS topic or another event destination. You're required to have a method of tracking bounces and complaints. If you haven't set up another mechanism for receiving bounce or complaint notifications, Amazon Pinpoint sends an email notification when these events occur (even if this setting is disabled).</p>
    pub fn get_feedback_forwarding_status(&self) -> &::std::option::Option<bool> {
        &self.feedback_forwarding_status
    }
    /// <p>Specifies whether or not the identity is verified. In Amazon Pinpoint, you can only send email from verified email addresses or domains. For more information about verifying identities, see the <a href="https://docs.aws.amazon.com/pinpoint/latest/userguide/channels-email-manage-verify.html">Amazon Pinpoint User Guide</a>.</p>
    pub fn verified_for_sending_status(mut self, input: bool) -> Self {
        self.verified_for_sending_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether or not the identity is verified. In Amazon Pinpoint, you can only send email from verified email addresses or domains. For more information about verifying identities, see the <a href="https://docs.aws.amazon.com/pinpoint/latest/userguide/channels-email-manage-verify.html">Amazon Pinpoint User Guide</a>.</p>
    pub fn set_verified_for_sending_status(mut self, input: ::std::option::Option<bool>) -> Self {
        self.verified_for_sending_status = input;
        self
    }
    /// <p>Specifies whether or not the identity is verified. In Amazon Pinpoint, you can only send email from verified email addresses or domains. For more information about verifying identities, see the <a href="https://docs.aws.amazon.com/pinpoint/latest/userguide/channels-email-manage-verify.html">Amazon Pinpoint User Guide</a>.</p>
    pub fn get_verified_for_sending_status(&self) -> &::std::option::Option<bool> {
        &self.verified_for_sending_status
    }
    /// <p>An object that contains information about the DKIM attributes for the identity. This object includes the tokens that you use to create the CNAME records that are required to complete the DKIM verification process.</p>
    pub fn dkim_attributes(mut self, input: crate::types::DkimAttributes) -> Self {
        self.dkim_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information about the DKIM attributes for the identity. This object includes the tokens that you use to create the CNAME records that are required to complete the DKIM verification process.</p>
    pub fn set_dkim_attributes(mut self, input: ::std::option::Option<crate::types::DkimAttributes>) -> Self {
        self.dkim_attributes = input;
        self
    }
    /// <p>An object that contains information about the DKIM attributes for the identity. This object includes the tokens that you use to create the CNAME records that are required to complete the DKIM verification process.</p>
    pub fn get_dkim_attributes(&self) -> &::std::option::Option<crate::types::DkimAttributes> {
        &self.dkim_attributes
    }
    /// <p>An object that contains information about the Mail-From attributes for the email identity.</p>
    pub fn mail_from_attributes(mut self, input: crate::types::MailFromAttributes) -> Self {
        self.mail_from_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information about the Mail-From attributes for the email identity.</p>
    pub fn set_mail_from_attributes(mut self, input: ::std::option::Option<crate::types::MailFromAttributes>) -> Self {
        self.mail_from_attributes = input;
        self
    }
    /// <p>An object that contains information about the Mail-From attributes for the email identity.</p>
    pub fn get_mail_from_attributes(&self) -> &::std::option::Option<crate::types::MailFromAttributes> {
        &self.mail_from_attributes
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An array of objects that define the tags (keys and values) that are associated with the email identity.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects that define the tags (keys and values) that are associated with the email identity.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An array of objects that define the tags (keys and values) that are associated with the email identity.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetEmailIdentityOutput`](crate::operation::get_email_identity::GetEmailIdentityOutput).
    pub fn build(self) -> crate::operation::get_email_identity::GetEmailIdentityOutput {
        crate::operation::get_email_identity::GetEmailIdentityOutput {
            identity_type: self.identity_type,
            feedback_forwarding_status: self.feedback_forwarding_status.unwrap_or_default(),
            verified_for_sending_status: self.verified_for_sending_status.unwrap_or_default(),
            dkim_attributes: self.dkim_attributes,
            mail_from_attributes: self.mail_from_attributes,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
