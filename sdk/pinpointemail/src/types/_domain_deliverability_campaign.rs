// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains the deliverability data for a specific campaign. This data is available for a campaign only if the campaign sent email by using a domain that the Deliverability dashboard is enabled for (<code>PutDeliverabilityDashboardOption</code> operation).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DomainDeliverabilityCampaign {
    /// <p>The unique identifier for the campaign. Amazon Pinpoint automatically generates and assigns this identifier to a campaign. This value is not the same as the campaign identifier that Amazon Pinpoint assigns to campaigns that you create and manage by using the Amazon Pinpoint API or the Amazon Pinpoint console.</p>
    pub campaign_id: ::std::option::Option<::std::string::String>,
    /// <p>The URL of an image that contains a snapshot of the email message that was sent.</p>
    pub image_url: ::std::option::Option<::std::string::String>,
    /// <p>The subject line, or title, of the email message.</p>
    pub subject: ::std::option::Option<::std::string::String>,
    /// <p>The verified email address that the email message was sent from.</p>
    pub from_address: ::std::option::Option<::std::string::String>,
    /// <p>The IP addresses that were used to send the email message.</p>
    pub sending_ips: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The first time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub first_seen_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The last time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub last_seen_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The number of email messages that were delivered to recipients’ inboxes.</p>
    pub inbox_count: ::std::option::Option<i64>,
    /// <p>The number of email messages that were delivered to recipients' spam or junk mail folders.</p>
    pub spam_count: ::std::option::Option<i64>,
    /// <p>The percentage of email messages that were opened by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub read_rate: ::std::option::Option<f64>,
    /// <p>The percentage of email messages that were deleted by recipients, without being opened first. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub delete_rate: ::std::option::Option<f64>,
    /// <p>The percentage of email messages that were opened and then deleted by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub read_delete_rate: ::std::option::Option<f64>,
    /// <p>The projected number of recipients that the email message was sent to.</p>
    pub projected_volume: ::std::option::Option<i64>,
    /// <p>The major email providers who handled the email message.</p>
    pub esps: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DomainDeliverabilityCampaign {
    /// <p>The unique identifier for the campaign. Amazon Pinpoint automatically generates and assigns this identifier to a campaign. This value is not the same as the campaign identifier that Amazon Pinpoint assigns to campaigns that you create and manage by using the Amazon Pinpoint API or the Amazon Pinpoint console.</p>
    pub fn campaign_id(&self) -> ::std::option::Option<&str> {
        self.campaign_id.as_deref()
    }
    /// <p>The URL of an image that contains a snapshot of the email message that was sent.</p>
    pub fn image_url(&self) -> ::std::option::Option<&str> {
        self.image_url.as_deref()
    }
    /// <p>The subject line, or title, of the email message.</p>
    pub fn subject(&self) -> ::std::option::Option<&str> {
        self.subject.as_deref()
    }
    /// <p>The verified email address that the email message was sent from.</p>
    pub fn from_address(&self) -> ::std::option::Option<&str> {
        self.from_address.as_deref()
    }
    /// <p>The IP addresses that were used to send the email message.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sending_ips.is_none()`.
    pub fn sending_ips(&self) -> &[::std::string::String] {
        self.sending_ips.as_deref().unwrap_or_default()
    }
    /// <p>The first time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub fn first_seen_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.first_seen_date_time.as_ref()
    }
    /// <p>The last time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub fn last_seen_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_seen_date_time.as_ref()
    }
    /// <p>The number of email messages that were delivered to recipients’ inboxes.</p>
    pub fn inbox_count(&self) -> ::std::option::Option<i64> {
        self.inbox_count
    }
    /// <p>The number of email messages that were delivered to recipients' spam or junk mail folders.</p>
    pub fn spam_count(&self) -> ::std::option::Option<i64> {
        self.spam_count
    }
    /// <p>The percentage of email messages that were opened by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn read_rate(&self) -> ::std::option::Option<f64> {
        self.read_rate
    }
    /// <p>The percentage of email messages that were deleted by recipients, without being opened first. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn delete_rate(&self) -> ::std::option::Option<f64> {
        self.delete_rate
    }
    /// <p>The percentage of email messages that were opened and then deleted by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn read_delete_rate(&self) -> ::std::option::Option<f64> {
        self.read_delete_rate
    }
    /// <p>The projected number of recipients that the email message was sent to.</p>
    pub fn projected_volume(&self) -> ::std::option::Option<i64> {
        self.projected_volume
    }
    /// <p>The major email providers who handled the email message.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.esps.is_none()`.
    pub fn esps(&self) -> &[::std::string::String] {
        self.esps.as_deref().unwrap_or_default()
    }
}
impl DomainDeliverabilityCampaign {
    /// Creates a new builder-style object to manufacture [`DomainDeliverabilityCampaign`](crate::types::DomainDeliverabilityCampaign).
    pub fn builder() -> crate::types::builders::DomainDeliverabilityCampaignBuilder {
        crate::types::builders::DomainDeliverabilityCampaignBuilder::default()
    }
}

/// A builder for [`DomainDeliverabilityCampaign`](crate::types::DomainDeliverabilityCampaign).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DomainDeliverabilityCampaignBuilder {
    pub(crate) campaign_id: ::std::option::Option<::std::string::String>,
    pub(crate) image_url: ::std::option::Option<::std::string::String>,
    pub(crate) subject: ::std::option::Option<::std::string::String>,
    pub(crate) from_address: ::std::option::Option<::std::string::String>,
    pub(crate) sending_ips: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) first_seen_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_seen_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) inbox_count: ::std::option::Option<i64>,
    pub(crate) spam_count: ::std::option::Option<i64>,
    pub(crate) read_rate: ::std::option::Option<f64>,
    pub(crate) delete_rate: ::std::option::Option<f64>,
    pub(crate) read_delete_rate: ::std::option::Option<f64>,
    pub(crate) projected_volume: ::std::option::Option<i64>,
    pub(crate) esps: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DomainDeliverabilityCampaignBuilder {
    /// <p>The unique identifier for the campaign. Amazon Pinpoint automatically generates and assigns this identifier to a campaign. This value is not the same as the campaign identifier that Amazon Pinpoint assigns to campaigns that you create and manage by using the Amazon Pinpoint API or the Amazon Pinpoint console.</p>
    pub fn campaign_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.campaign_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the campaign. Amazon Pinpoint automatically generates and assigns this identifier to a campaign. This value is not the same as the campaign identifier that Amazon Pinpoint assigns to campaigns that you create and manage by using the Amazon Pinpoint API or the Amazon Pinpoint console.</p>
    pub fn set_campaign_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.campaign_id = input;
        self
    }
    /// <p>The unique identifier for the campaign. Amazon Pinpoint automatically generates and assigns this identifier to a campaign. This value is not the same as the campaign identifier that Amazon Pinpoint assigns to campaigns that you create and manage by using the Amazon Pinpoint API or the Amazon Pinpoint console.</p>
    pub fn get_campaign_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.campaign_id
    }
    /// <p>The URL of an image that contains a snapshot of the email message that was sent.</p>
    pub fn image_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of an image that contains a snapshot of the email message that was sent.</p>
    pub fn set_image_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_url = input;
        self
    }
    /// <p>The URL of an image that contains a snapshot of the email message that was sent.</p>
    pub fn get_image_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_url
    }
    /// <p>The subject line, or title, of the email message.</p>
    pub fn subject(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subject line, or title, of the email message.</p>
    pub fn set_subject(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject = input;
        self
    }
    /// <p>The subject line, or title, of the email message.</p>
    pub fn get_subject(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject
    }
    /// <p>The verified email address that the email message was sent from.</p>
    pub fn from_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.from_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The verified email address that the email message was sent from.</p>
    pub fn set_from_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.from_address = input;
        self
    }
    /// <p>The verified email address that the email message was sent from.</p>
    pub fn get_from_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.from_address
    }
    /// Appends an item to `sending_ips`.
    ///
    /// To override the contents of this collection use [`set_sending_ips`](Self::set_sending_ips).
    ///
    /// <p>The IP addresses that were used to send the email message.</p>
    pub fn sending_ips(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.sending_ips.unwrap_or_default();
        v.push(input.into());
        self.sending_ips = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IP addresses that were used to send the email message.</p>
    pub fn set_sending_ips(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.sending_ips = input;
        self
    }
    /// <p>The IP addresses that were used to send the email message.</p>
    pub fn get_sending_ips(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.sending_ips
    }
    /// <p>The first time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub fn first_seen_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.first_seen_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The first time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub fn set_first_seen_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.first_seen_date_time = input;
        self
    }
    /// <p>The first time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub fn get_first_seen_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.first_seen_date_time
    }
    /// <p>The last time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub fn last_seen_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_seen_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub fn set_last_seen_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_seen_date_time = input;
        self
    }
    /// <p>The last time, in Unix time format, when the email message was delivered to any recipient's inbox. This value can help you determine how long it took for a campaign to deliver an email message.</p>
    pub fn get_last_seen_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_seen_date_time
    }
    /// <p>The number of email messages that were delivered to recipients’ inboxes.</p>
    pub fn inbox_count(mut self, input: i64) -> Self {
        self.inbox_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of email messages that were delivered to recipients’ inboxes.</p>
    pub fn set_inbox_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.inbox_count = input;
        self
    }
    /// <p>The number of email messages that were delivered to recipients’ inboxes.</p>
    pub fn get_inbox_count(&self) -> &::std::option::Option<i64> {
        &self.inbox_count
    }
    /// <p>The number of email messages that were delivered to recipients' spam or junk mail folders.</p>
    pub fn spam_count(mut self, input: i64) -> Self {
        self.spam_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of email messages that were delivered to recipients' spam or junk mail folders.</p>
    pub fn set_spam_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.spam_count = input;
        self
    }
    /// <p>The number of email messages that were delivered to recipients' spam or junk mail folders.</p>
    pub fn get_spam_count(&self) -> &::std::option::Option<i64> {
        &self.spam_count
    }
    /// <p>The percentage of email messages that were opened by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn read_rate(mut self, input: f64) -> Self {
        self.read_rate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage of email messages that were opened by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn set_read_rate(mut self, input: ::std::option::Option<f64>) -> Self {
        self.read_rate = input;
        self
    }
    /// <p>The percentage of email messages that were opened by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn get_read_rate(&self) -> &::std::option::Option<f64> {
        &self.read_rate
    }
    /// <p>The percentage of email messages that were deleted by recipients, without being opened first. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn delete_rate(mut self, input: f64) -> Self {
        self.delete_rate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage of email messages that were deleted by recipients, without being opened first. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn set_delete_rate(mut self, input: ::std::option::Option<f64>) -> Self {
        self.delete_rate = input;
        self
    }
    /// <p>The percentage of email messages that were deleted by recipients, without being opened first. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn get_delete_rate(&self) -> &::std::option::Option<f64> {
        &self.delete_rate
    }
    /// <p>The percentage of email messages that were opened and then deleted by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn read_delete_rate(mut self, input: f64) -> Self {
        self.read_delete_rate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage of email messages that were opened and then deleted by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn set_read_delete_rate(mut self, input: ::std::option::Option<f64>) -> Self {
        self.read_delete_rate = input;
        self
    }
    /// <p>The percentage of email messages that were opened and then deleted by recipients. Due to technical limitations, this value only includes recipients who opened the message by using an email client that supports images.</p>
    pub fn get_read_delete_rate(&self) -> &::std::option::Option<f64> {
        &self.read_delete_rate
    }
    /// <p>The projected number of recipients that the email message was sent to.</p>
    pub fn projected_volume(mut self, input: i64) -> Self {
        self.projected_volume = ::std::option::Option::Some(input);
        self
    }
    /// <p>The projected number of recipients that the email message was sent to.</p>
    pub fn set_projected_volume(mut self, input: ::std::option::Option<i64>) -> Self {
        self.projected_volume = input;
        self
    }
    /// <p>The projected number of recipients that the email message was sent to.</p>
    pub fn get_projected_volume(&self) -> &::std::option::Option<i64> {
        &self.projected_volume
    }
    /// Appends an item to `esps`.
    ///
    /// To override the contents of this collection use [`set_esps`](Self::set_esps).
    ///
    /// <p>The major email providers who handled the email message.</p>
    pub fn esps(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.esps.unwrap_or_default();
        v.push(input.into());
        self.esps = ::std::option::Option::Some(v);
        self
    }
    /// <p>The major email providers who handled the email message.</p>
    pub fn set_esps(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.esps = input;
        self
    }
    /// <p>The major email providers who handled the email message.</p>
    pub fn get_esps(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.esps
    }
    /// Consumes the builder and constructs a [`DomainDeliverabilityCampaign`](crate::types::DomainDeliverabilityCampaign).
    pub fn build(self) -> crate::types::DomainDeliverabilityCampaign {
        crate::types::DomainDeliverabilityCampaign {
            campaign_id: self.campaign_id,
            image_url: self.image_url,
            subject: self.subject,
            from_address: self.from_address,
            sending_ips: self.sending_ips,
            first_seen_date_time: self.first_seen_date_time,
            last_seen_date_time: self.last_seen_date_time,
            inbox_count: self.inbox_count,
            spam_count: self.spam_count,
            read_rate: self.read_rate,
            delete_rate: self.delete_rate,
            read_delete_rate: self.read_delete_rate,
            projected_volume: self.projected_volume,
            esps: self.esps,
        }
    }
}
