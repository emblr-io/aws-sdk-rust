// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a phone number that has been claimed to your Amazon Connect instance or traffic distribution group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClaimedPhoneNumberSummary {
    /// <p>A unique identifier for the phone number.</p>
    pub phone_number_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the phone number.</p>
    pub phone_number_arn: ::std::option::Option<::std::string::String>,
    /// <p>The phone number. Phone numbers are formatted <code>\[+\] \[country code\] \[subscriber number including area code\]</code>.</p>
    pub phone_number: ::std::option::Option<::std::string::String>,
    /// <p>The ISO country code.</p>
    pub phone_number_country_code: ::std::option::Option<crate::types::PhoneNumberCountryCode>,
    /// <p>The type of phone number.</p>
    pub phone_number_type: ::std::option::Option<crate::types::PhoneNumberType>,
    /// <p>The description of the phone number.</p>
    pub phone_number_description: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for Amazon Connect instances or traffic distribution groups that phone number inbound traffic is routed through.</p>
    pub target_arn: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the Amazon Connect instance that phone numbers are claimed to. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The tags used to organize, track, or control access for this resource. For example, { "Tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The status of the phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLAIMED</code> means the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation succeeded.</p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code> means a <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a>, <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a>, or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumberMetadata.html">UpdatePhoneNumberMetadata</a> operation is still in progress and has not yet completed. You can call <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_DescribePhoneNumber.html">DescribePhoneNumber</a> at a later time to verify if the previous operation has completed.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation has failed. It will include a message indicating the failure reason. A common reason for a failure may be that the <code>TargetArn</code> value you are claiming or updating a phone number to has reached its limit of total claimed numbers. If you received a <code>FAILED</code> status from a <code>ClaimPhoneNumber</code> API call, you have one day to retry claiming the phone number before the number is released back to the inventory for other customers to claim.</p></li>
    /// </ul><note>
    /// <p>You will not be billed for the phone number during the 1-day period if number claiming fails.</p>
    /// </note>
    pub phone_number_status: ::std::option::Option<crate::types::PhoneNumberStatus>,
    /// <p>The claimed phone number ARN that was previously imported from the external service, such as Amazon Web Services End User Messaging. If it is from Amazon Web Services End User Messaging, it looks like the ARN of the phone number that was imported from Amazon Web Services End User Messaging.</p>
    pub source_phone_number_arn: ::std::option::Option<::std::string::String>,
}
impl ClaimedPhoneNumberSummary {
    /// <p>A unique identifier for the phone number.</p>
    pub fn phone_number_id(&self) -> ::std::option::Option<&str> {
        self.phone_number_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the phone number.</p>
    pub fn phone_number_arn(&self) -> ::std::option::Option<&str> {
        self.phone_number_arn.as_deref()
    }
    /// <p>The phone number. Phone numbers are formatted <code>\[+\] \[country code\] \[subscriber number including area code\]</code>.</p>
    pub fn phone_number(&self) -> ::std::option::Option<&str> {
        self.phone_number.as_deref()
    }
    /// <p>The ISO country code.</p>
    pub fn phone_number_country_code(&self) -> ::std::option::Option<&crate::types::PhoneNumberCountryCode> {
        self.phone_number_country_code.as_ref()
    }
    /// <p>The type of phone number.</p>
    pub fn phone_number_type(&self) -> ::std::option::Option<&crate::types::PhoneNumberType> {
        self.phone_number_type.as_ref()
    }
    /// <p>The description of the phone number.</p>
    pub fn phone_number_description(&self) -> ::std::option::Option<&str> {
        self.phone_number_description.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for Amazon Connect instances or traffic distribution groups that phone number inbound traffic is routed through.</p>
    pub fn target_arn(&self) -> ::std::option::Option<&str> {
        self.target_arn.as_deref()
    }
    /// <p>The identifier of the Amazon Connect instance that phone numbers are claimed to. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The tags used to organize, track, or control access for this resource. For example, { "Tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The status of the phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLAIMED</code> means the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation succeeded.</p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code> means a <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a>, <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a>, or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumberMetadata.html">UpdatePhoneNumberMetadata</a> operation is still in progress and has not yet completed. You can call <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_DescribePhoneNumber.html">DescribePhoneNumber</a> at a later time to verify if the previous operation has completed.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation has failed. It will include a message indicating the failure reason. A common reason for a failure may be that the <code>TargetArn</code> value you are claiming or updating a phone number to has reached its limit of total claimed numbers. If you received a <code>FAILED</code> status from a <code>ClaimPhoneNumber</code> API call, you have one day to retry claiming the phone number before the number is released back to the inventory for other customers to claim.</p></li>
    /// </ul><note>
    /// <p>You will not be billed for the phone number during the 1-day period if number claiming fails.</p>
    /// </note>
    pub fn phone_number_status(&self) -> ::std::option::Option<&crate::types::PhoneNumberStatus> {
        self.phone_number_status.as_ref()
    }
    /// <p>The claimed phone number ARN that was previously imported from the external service, such as Amazon Web Services End User Messaging. If it is from Amazon Web Services End User Messaging, it looks like the ARN of the phone number that was imported from Amazon Web Services End User Messaging.</p>
    pub fn source_phone_number_arn(&self) -> ::std::option::Option<&str> {
        self.source_phone_number_arn.as_deref()
    }
}
impl ClaimedPhoneNumberSummary {
    /// Creates a new builder-style object to manufacture [`ClaimedPhoneNumberSummary`](crate::types::ClaimedPhoneNumberSummary).
    pub fn builder() -> crate::types::builders::ClaimedPhoneNumberSummaryBuilder {
        crate::types::builders::ClaimedPhoneNumberSummaryBuilder::default()
    }
}

/// A builder for [`ClaimedPhoneNumberSummary`](crate::types::ClaimedPhoneNumberSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClaimedPhoneNumberSummaryBuilder {
    pub(crate) phone_number_id: ::std::option::Option<::std::string::String>,
    pub(crate) phone_number_arn: ::std::option::Option<::std::string::String>,
    pub(crate) phone_number: ::std::option::Option<::std::string::String>,
    pub(crate) phone_number_country_code: ::std::option::Option<crate::types::PhoneNumberCountryCode>,
    pub(crate) phone_number_type: ::std::option::Option<crate::types::PhoneNumberType>,
    pub(crate) phone_number_description: ::std::option::Option<::std::string::String>,
    pub(crate) target_arn: ::std::option::Option<::std::string::String>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) phone_number_status: ::std::option::Option<crate::types::PhoneNumberStatus>,
    pub(crate) source_phone_number_arn: ::std::option::Option<::std::string::String>,
}
impl ClaimedPhoneNumberSummaryBuilder {
    /// <p>A unique identifier for the phone number.</p>
    pub fn phone_number_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.phone_number_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the phone number.</p>
    pub fn set_phone_number_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.phone_number_id = input;
        self
    }
    /// <p>A unique identifier for the phone number.</p>
    pub fn get_phone_number_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.phone_number_id
    }
    /// <p>The Amazon Resource Name (ARN) of the phone number.</p>
    pub fn phone_number_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.phone_number_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the phone number.</p>
    pub fn set_phone_number_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.phone_number_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the phone number.</p>
    pub fn get_phone_number_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.phone_number_arn
    }
    /// <p>The phone number. Phone numbers are formatted <code>\[+\] \[country code\] \[subscriber number including area code\]</code>.</p>
    pub fn phone_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.phone_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The phone number. Phone numbers are formatted <code>\[+\] \[country code\] \[subscriber number including area code\]</code>.</p>
    pub fn set_phone_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.phone_number = input;
        self
    }
    /// <p>The phone number. Phone numbers are formatted <code>\[+\] \[country code\] \[subscriber number including area code\]</code>.</p>
    pub fn get_phone_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.phone_number
    }
    /// <p>The ISO country code.</p>
    pub fn phone_number_country_code(mut self, input: crate::types::PhoneNumberCountryCode) -> Self {
        self.phone_number_country_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ISO country code.</p>
    pub fn set_phone_number_country_code(mut self, input: ::std::option::Option<crate::types::PhoneNumberCountryCode>) -> Self {
        self.phone_number_country_code = input;
        self
    }
    /// <p>The ISO country code.</p>
    pub fn get_phone_number_country_code(&self) -> &::std::option::Option<crate::types::PhoneNumberCountryCode> {
        &self.phone_number_country_code
    }
    /// <p>The type of phone number.</p>
    pub fn phone_number_type(mut self, input: crate::types::PhoneNumberType) -> Self {
        self.phone_number_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of phone number.</p>
    pub fn set_phone_number_type(mut self, input: ::std::option::Option<crate::types::PhoneNumberType>) -> Self {
        self.phone_number_type = input;
        self
    }
    /// <p>The type of phone number.</p>
    pub fn get_phone_number_type(&self) -> &::std::option::Option<crate::types::PhoneNumberType> {
        &self.phone_number_type
    }
    /// <p>The description of the phone number.</p>
    pub fn phone_number_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.phone_number_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the phone number.</p>
    pub fn set_phone_number_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.phone_number_description = input;
        self
    }
    /// <p>The description of the phone number.</p>
    pub fn get_phone_number_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.phone_number_description
    }
    /// <p>The Amazon Resource Name (ARN) for Amazon Connect instances or traffic distribution groups that phone number inbound traffic is routed through.</p>
    pub fn target_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for Amazon Connect instances or traffic distribution groups that phone number inbound traffic is routed through.</p>
    pub fn set_target_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for Amazon Connect instances or traffic distribution groups that phone number inbound traffic is routed through.</p>
    pub fn get_target_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_arn
    }
    /// <p>The identifier of the Amazon Connect instance that phone numbers are claimed to. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance that phone numbers are claimed to. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance that phone numbers are claimed to. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags used to organize, track, or control access for this resource. For example, { "Tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource. For example, { "Tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource. For example, { "Tags": {"key1":"value1", "key2":"value2"} }.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The status of the phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLAIMED</code> means the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation succeeded.</p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code> means a <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a>, <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a>, or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumberMetadata.html">UpdatePhoneNumberMetadata</a> operation is still in progress and has not yet completed. You can call <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_DescribePhoneNumber.html">DescribePhoneNumber</a> at a later time to verify if the previous operation has completed.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation has failed. It will include a message indicating the failure reason. A common reason for a failure may be that the <code>TargetArn</code> value you are claiming or updating a phone number to has reached its limit of total claimed numbers. If you received a <code>FAILED</code> status from a <code>ClaimPhoneNumber</code> API call, you have one day to retry claiming the phone number before the number is released back to the inventory for other customers to claim.</p></li>
    /// </ul><note>
    /// <p>You will not be billed for the phone number during the 1-day period if number claiming fails.</p>
    /// </note>
    pub fn phone_number_status(mut self, input: crate::types::PhoneNumberStatus) -> Self {
        self.phone_number_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLAIMED</code> means the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation succeeded.</p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code> means a <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a>, <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a>, or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumberMetadata.html">UpdatePhoneNumberMetadata</a> operation is still in progress and has not yet completed. You can call <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_DescribePhoneNumber.html">DescribePhoneNumber</a> at a later time to verify if the previous operation has completed.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation has failed. It will include a message indicating the failure reason. A common reason for a failure may be that the <code>TargetArn</code> value you are claiming or updating a phone number to has reached its limit of total claimed numbers. If you received a <code>FAILED</code> status from a <code>ClaimPhoneNumber</code> API call, you have one day to retry claiming the phone number before the number is released back to the inventory for other customers to claim.</p></li>
    /// </ul><note>
    /// <p>You will not be billed for the phone number during the 1-day period if number claiming fails.</p>
    /// </note>
    pub fn set_phone_number_status(mut self, input: ::std::option::Option<crate::types::PhoneNumberStatus>) -> Self {
        self.phone_number_status = input;
        self
    }
    /// <p>The status of the phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLAIMED</code> means the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation succeeded.</p></li>
    /// <li>
    /// <p><code>IN_PROGRESS</code> means a <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a>, <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a>, or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumberMetadata.html">UpdatePhoneNumberMetadata</a> operation is still in progress and has not yet completed. You can call <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_DescribePhoneNumber.html">DescribePhoneNumber</a> at a later time to verify if the previous operation has completed.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the previous <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_ClaimPhoneNumber.html">ClaimPhoneNumber</a> or <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_UpdatePhoneNumber.html">UpdatePhoneNumber</a> operation has failed. It will include a message indicating the failure reason. A common reason for a failure may be that the <code>TargetArn</code> value you are claiming or updating a phone number to has reached its limit of total claimed numbers. If you received a <code>FAILED</code> status from a <code>ClaimPhoneNumber</code> API call, you have one day to retry claiming the phone number before the number is released back to the inventory for other customers to claim.</p></li>
    /// </ul><note>
    /// <p>You will not be billed for the phone number during the 1-day period if number claiming fails.</p>
    /// </note>
    pub fn get_phone_number_status(&self) -> &::std::option::Option<crate::types::PhoneNumberStatus> {
        &self.phone_number_status
    }
    /// <p>The claimed phone number ARN that was previously imported from the external service, such as Amazon Web Services End User Messaging. If it is from Amazon Web Services End User Messaging, it looks like the ARN of the phone number that was imported from Amazon Web Services End User Messaging.</p>
    pub fn source_phone_number_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_phone_number_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The claimed phone number ARN that was previously imported from the external service, such as Amazon Web Services End User Messaging. If it is from Amazon Web Services End User Messaging, it looks like the ARN of the phone number that was imported from Amazon Web Services End User Messaging.</p>
    pub fn set_source_phone_number_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_phone_number_arn = input;
        self
    }
    /// <p>The claimed phone number ARN that was previously imported from the external service, such as Amazon Web Services End User Messaging. If it is from Amazon Web Services End User Messaging, it looks like the ARN of the phone number that was imported from Amazon Web Services End User Messaging.</p>
    pub fn get_source_phone_number_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_phone_number_arn
    }
    /// Consumes the builder and constructs a [`ClaimedPhoneNumberSummary`](crate::types::ClaimedPhoneNumberSummary).
    pub fn build(self) -> crate::types::ClaimedPhoneNumberSummary {
        crate::types::ClaimedPhoneNumberSummary {
            phone_number_id: self.phone_number_id,
            phone_number_arn: self.phone_number_arn,
            phone_number: self.phone_number,
            phone_number_country_code: self.phone_number_country_code,
            phone_number_type: self.phone_number_type,
            phone_number_description: self.phone_number_description,
            target_arn: self.target_arn,
            instance_id: self.instance_id,
            tags: self.tags,
            phone_number_status: self.phone_number_status,
            source_phone_number_arn: self.source_phone_number_arn,
        }
    }
}
