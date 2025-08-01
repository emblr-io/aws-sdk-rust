// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Detailed information about an event. A combination of an <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_Event.html">Event</a> object, an <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_EventDescription.html">EventDescription</a> object, and additional metadata about the event. Returned by the <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetailsForOrganization.html">DescribeEventDetailsForOrganization</a> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OrganizationEventDetails {
    /// <p>The 12-digit Amazon Web Services account numbers that contains the affected entities.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>Summary information about an Health event.</p>
    /// <p>Health events can be public or account-specific:</p>
    /// <ul>
    /// <li>
    /// <p><i>Public events</i> might be service events that are not specific to an Amazon Web Services account. For example, if there is an issue with an Amazon Web Services Region, Health provides information about the event, even if you don't use services or resources in that Region.</p></li>
    /// <li>
    /// <p><i>Account-specific</i> events are specific to either your Amazon Web Services account or an account in your organization. For example, if there's an issue with Amazon Elastic Compute Cloud in a Region that you use, Health provides information about the event and the affected resources in the account.</p></li>
    /// </ul>
    /// <p>You can determine if an event is public or account-specific by using the <code>eventScopeCode</code> parameter. For more information, see <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_Event.html#AWSHealth-Type-Event-eventScopeCode">eventScopeCode</a>.</p>
    pub event: ::std::option::Option<crate::types::Event>,
    /// <p>The detailed description of the event. Included in the information returned by the <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetails.html">DescribeEventDetails</a> operation.</p>
    pub event_description: ::std::option::Option<crate::types::EventDescription>,
    /// <p>Additional metadata about the event.</p>
    pub event_metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl OrganizationEventDetails {
    /// <p>The 12-digit Amazon Web Services account numbers that contains the affected entities.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>Summary information about an Health event.</p>
    /// <p>Health events can be public or account-specific:</p>
    /// <ul>
    /// <li>
    /// <p><i>Public events</i> might be service events that are not specific to an Amazon Web Services account. For example, if there is an issue with an Amazon Web Services Region, Health provides information about the event, even if you don't use services or resources in that Region.</p></li>
    /// <li>
    /// <p><i>Account-specific</i> events are specific to either your Amazon Web Services account or an account in your organization. For example, if there's an issue with Amazon Elastic Compute Cloud in a Region that you use, Health provides information about the event and the affected resources in the account.</p></li>
    /// </ul>
    /// <p>You can determine if an event is public or account-specific by using the <code>eventScopeCode</code> parameter. For more information, see <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_Event.html#AWSHealth-Type-Event-eventScopeCode">eventScopeCode</a>.</p>
    pub fn event(&self) -> ::std::option::Option<&crate::types::Event> {
        self.event.as_ref()
    }
    /// <p>The detailed description of the event. Included in the information returned by the <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetails.html">DescribeEventDetails</a> operation.</p>
    pub fn event_description(&self) -> ::std::option::Option<&crate::types::EventDescription> {
        self.event_description.as_ref()
    }
    /// <p>Additional metadata about the event.</p>
    pub fn event_metadata(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.event_metadata.as_ref()
    }
}
impl OrganizationEventDetails {
    /// Creates a new builder-style object to manufacture [`OrganizationEventDetails`](crate::types::OrganizationEventDetails).
    pub fn builder() -> crate::types::builders::OrganizationEventDetailsBuilder {
        crate::types::builders::OrganizationEventDetailsBuilder::default()
    }
}

/// A builder for [`OrganizationEventDetails`](crate::types::OrganizationEventDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OrganizationEventDetailsBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) event: ::std::option::Option<crate::types::Event>,
    pub(crate) event_description: ::std::option::Option<crate::types::EventDescription>,
    pub(crate) event_metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl OrganizationEventDetailsBuilder {
    /// <p>The 12-digit Amazon Web Services account numbers that contains the affected entities.</p>
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The 12-digit Amazon Web Services account numbers that contains the affected entities.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The 12-digit Amazon Web Services account numbers that contains the affected entities.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>Summary information about an Health event.</p>
    /// <p>Health events can be public or account-specific:</p>
    /// <ul>
    /// <li>
    /// <p><i>Public events</i> might be service events that are not specific to an Amazon Web Services account. For example, if there is an issue with an Amazon Web Services Region, Health provides information about the event, even if you don't use services or resources in that Region.</p></li>
    /// <li>
    /// <p><i>Account-specific</i> events are specific to either your Amazon Web Services account or an account in your organization. For example, if there's an issue with Amazon Elastic Compute Cloud in a Region that you use, Health provides information about the event and the affected resources in the account.</p></li>
    /// </ul>
    /// <p>You can determine if an event is public or account-specific by using the <code>eventScopeCode</code> parameter. For more information, see <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_Event.html#AWSHealth-Type-Event-eventScopeCode">eventScopeCode</a>.</p>
    pub fn event(mut self, input: crate::types::Event) -> Self {
        self.event = ::std::option::Option::Some(input);
        self
    }
    /// <p>Summary information about an Health event.</p>
    /// <p>Health events can be public or account-specific:</p>
    /// <ul>
    /// <li>
    /// <p><i>Public events</i> might be service events that are not specific to an Amazon Web Services account. For example, if there is an issue with an Amazon Web Services Region, Health provides information about the event, even if you don't use services or resources in that Region.</p></li>
    /// <li>
    /// <p><i>Account-specific</i> events are specific to either your Amazon Web Services account or an account in your organization. For example, if there's an issue with Amazon Elastic Compute Cloud in a Region that you use, Health provides information about the event and the affected resources in the account.</p></li>
    /// </ul>
    /// <p>You can determine if an event is public or account-specific by using the <code>eventScopeCode</code> parameter. For more information, see <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_Event.html#AWSHealth-Type-Event-eventScopeCode">eventScopeCode</a>.</p>
    pub fn set_event(mut self, input: ::std::option::Option<crate::types::Event>) -> Self {
        self.event = input;
        self
    }
    /// <p>Summary information about an Health event.</p>
    /// <p>Health events can be public or account-specific:</p>
    /// <ul>
    /// <li>
    /// <p><i>Public events</i> might be service events that are not specific to an Amazon Web Services account. For example, if there is an issue with an Amazon Web Services Region, Health provides information about the event, even if you don't use services or resources in that Region.</p></li>
    /// <li>
    /// <p><i>Account-specific</i> events are specific to either your Amazon Web Services account or an account in your organization. For example, if there's an issue with Amazon Elastic Compute Cloud in a Region that you use, Health provides information about the event and the affected resources in the account.</p></li>
    /// </ul>
    /// <p>You can determine if an event is public or account-specific by using the <code>eventScopeCode</code> parameter. For more information, see <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_Event.html#AWSHealth-Type-Event-eventScopeCode">eventScopeCode</a>.</p>
    pub fn get_event(&self) -> &::std::option::Option<crate::types::Event> {
        &self.event
    }
    /// <p>The detailed description of the event. Included in the information returned by the <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetails.html">DescribeEventDetails</a> operation.</p>
    pub fn event_description(mut self, input: crate::types::EventDescription) -> Self {
        self.event_description = ::std::option::Option::Some(input);
        self
    }
    /// <p>The detailed description of the event. Included in the information returned by the <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetails.html">DescribeEventDetails</a> operation.</p>
    pub fn set_event_description(mut self, input: ::std::option::Option<crate::types::EventDescription>) -> Self {
        self.event_description = input;
        self
    }
    /// <p>The detailed description of the event. Included in the information returned by the <a href="https://docs.aws.amazon.com/health/latest/APIReference/API_DescribeEventDetails.html">DescribeEventDetails</a> operation.</p>
    pub fn get_event_description(&self) -> &::std::option::Option<crate::types::EventDescription> {
        &self.event_description
    }
    /// Adds a key-value pair to `event_metadata`.
    ///
    /// To override the contents of this collection use [`set_event_metadata`](Self::set_event_metadata).
    ///
    /// <p>Additional metadata about the event.</p>
    pub fn event_metadata(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.event_metadata.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.event_metadata = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Additional metadata about the event.</p>
    pub fn set_event_metadata(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.event_metadata = input;
        self
    }
    /// <p>Additional metadata about the event.</p>
    pub fn get_event_metadata(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.event_metadata
    }
    /// Consumes the builder and constructs a [`OrganizationEventDetails`](crate::types::OrganizationEventDetails).
    pub fn build(self) -> crate::types::OrganizationEventDetails {
        crate::types::OrganizationEventDetails {
            aws_account_id: self.aws_account_id,
            event: self.event,
            event_description: self.event_description,
            event_metadata: self.event_metadata,
        }
    }
}
