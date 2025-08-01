// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the signals involved in an Amazon GuardDuty Extended Threat Detection attack sequence. An attack sequence is a type of threat detected by GuardDuty. GuardDuty generates an attack sequence finding when multiple events, or signals, align to a potentially suspicious activity. When GuardDuty and Security Hub are integrated, GuardDuty sends attack sequence findings to Security Hub.</p>
/// <p>A signal can be an API activity or a finding that GuardDuty uses to detect an attack sequence finding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Signal {
    /// <p>The type of the signal used to identify an attack sequence.</p>
    /// <p>Signals can be GuardDuty findings or activities observed in data sources that GuardDuty monitors. For more information, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html">GuardDuty foundational data sources</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    /// <p>A signal type can be one of the following values. Here are the related descriptions:</p>
    /// <ul>
    /// <li>
    /// <p><code>FINDING</code> - Individually generated GuardDuty finding.</p></li>
    /// <li>
    /// <p><code>CLOUD_TRAIL</code> - Activity observed from CloudTrail logs</p></li>
    /// <li>
    /// <p><code>S3_DATA_EVENTS</code> - Activity observed from CloudTrail data events for Amazon Simple Storage Service (S3). Activities associated with this type will show up only when you have enabled GuardDuty S3 Protection feature in your account. For more information about S3 Protection and the steps to enable it, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html">S3 Protection</a> in the <i>Amazon GuardDuty User Guide</i>.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the signal.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The description of the GuardDuty finding.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the product that generated the signal.</p>
    pub product_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN or ID of the Amazon Web Services resource associated with the signal.</p>
    pub resource_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Contains information about the indicators associated with the signals in this attack sequence finding. The values for <code>SignalIndicators</code> are a subset of the values for <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Sequence.html">SequenceIndicators</a>, but the values for these fields don't always match 1:1.</p>
    pub signal_indicators: ::std::option::Option<::std::vec::Vec<crate::types::Indicator>>,
    /// <p>The name of the GuardDuty signal. For example, when signal type is <code>FINDING</code>, the signal name is the name of the finding.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub created_at: ::std::option::Option<i64>,
    /// <p>The timestamp when this signal was last observed.</p>
    pub updated_at: ::std::option::Option<i64>,
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub first_seen_at: ::std::option::Option<i64>,
    /// <p>The timestamp when the last finding or activity related to this signal was observed.</p>
    pub last_seen_at: ::std::option::Option<i64>,
    /// <p>The severity associated with the signal. For more information about severity, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html">Severity levels for GuardDuty findings</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    pub severity: ::std::option::Option<f64>,
    /// <p>The number of times this signal was observed.</p>
    pub count: ::std::option::Option<i32>,
    /// <p>The IDs of the threat actors involved in the signal.</p>
    pub actor_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Information about the endpoint IDs associated with this signal.</p>
    pub endpoint_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl Signal {
    /// <p>The type of the signal used to identify an attack sequence.</p>
    /// <p>Signals can be GuardDuty findings or activities observed in data sources that GuardDuty monitors. For more information, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html">GuardDuty foundational data sources</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    /// <p>A signal type can be one of the following values. Here are the related descriptions:</p>
    /// <ul>
    /// <li>
    /// <p><code>FINDING</code> - Individually generated GuardDuty finding.</p></li>
    /// <li>
    /// <p><code>CLOUD_TRAIL</code> - Activity observed from CloudTrail logs</p></li>
    /// <li>
    /// <p><code>S3_DATA_EVENTS</code> - Activity observed from CloudTrail data events for Amazon Simple Storage Service (S3). Activities associated with this type will show up only when you have enabled GuardDuty S3 Protection feature in your account. For more information about S3 Protection and the steps to enable it, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html">S3 Protection</a> in the <i>Amazon GuardDuty User Guide</i>.</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The identifier of the signal.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The description of the GuardDuty finding.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the product that generated the signal.</p>
    pub fn product_arn(&self) -> ::std::option::Option<&str> {
        self.product_arn.as_deref()
    }
    /// <p>The ARN or ID of the Amazon Web Services resource associated with the signal.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_ids.is_none()`.
    pub fn resource_ids(&self) -> &[::std::string::String] {
        self.resource_ids.as_deref().unwrap_or_default()
    }
    /// <p>Contains information about the indicators associated with the signals in this attack sequence finding. The values for <code>SignalIndicators</code> are a subset of the values for <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Sequence.html">SequenceIndicators</a>, but the values for these fields don't always match 1:1.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.signal_indicators.is_none()`.
    pub fn signal_indicators(&self) -> &[crate::types::Indicator] {
        self.signal_indicators.as_deref().unwrap_or_default()
    }
    /// <p>The name of the GuardDuty signal. For example, when signal type is <code>FINDING</code>, the signal name is the name of the finding.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub fn created_at(&self) -> ::std::option::Option<i64> {
        self.created_at
    }
    /// <p>The timestamp when this signal was last observed.</p>
    pub fn updated_at(&self) -> ::std::option::Option<i64> {
        self.updated_at
    }
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub fn first_seen_at(&self) -> ::std::option::Option<i64> {
        self.first_seen_at
    }
    /// <p>The timestamp when the last finding or activity related to this signal was observed.</p>
    pub fn last_seen_at(&self) -> ::std::option::Option<i64> {
        self.last_seen_at
    }
    /// <p>The severity associated with the signal. For more information about severity, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html">Severity levels for GuardDuty findings</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    pub fn severity(&self) -> ::std::option::Option<f64> {
        self.severity
    }
    /// <p>The number of times this signal was observed.</p>
    pub fn count(&self) -> ::std::option::Option<i32> {
        self.count
    }
    /// <p>The IDs of the threat actors involved in the signal.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.actor_ids.is_none()`.
    pub fn actor_ids(&self) -> &[::std::string::String] {
        self.actor_ids.as_deref().unwrap_or_default()
    }
    /// <p>Information about the endpoint IDs associated with this signal.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.endpoint_ids.is_none()`.
    pub fn endpoint_ids(&self) -> &[::std::string::String] {
        self.endpoint_ids.as_deref().unwrap_or_default()
    }
}
impl Signal {
    /// Creates a new builder-style object to manufacture [`Signal`](crate::types::Signal).
    pub fn builder() -> crate::types::builders::SignalBuilder {
        crate::types::builders::SignalBuilder::default()
    }
}

/// A builder for [`Signal`](crate::types::Signal).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SignalBuilder {
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) product_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) signal_indicators: ::std::option::Option<::std::vec::Vec<crate::types::Indicator>>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<i64>,
    pub(crate) updated_at: ::std::option::Option<i64>,
    pub(crate) first_seen_at: ::std::option::Option<i64>,
    pub(crate) last_seen_at: ::std::option::Option<i64>,
    pub(crate) severity: ::std::option::Option<f64>,
    pub(crate) count: ::std::option::Option<i32>,
    pub(crate) actor_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) endpoint_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SignalBuilder {
    /// <p>The type of the signal used to identify an attack sequence.</p>
    /// <p>Signals can be GuardDuty findings or activities observed in data sources that GuardDuty monitors. For more information, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html">GuardDuty foundational data sources</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    /// <p>A signal type can be one of the following values. Here are the related descriptions:</p>
    /// <ul>
    /// <li>
    /// <p><code>FINDING</code> - Individually generated GuardDuty finding.</p></li>
    /// <li>
    /// <p><code>CLOUD_TRAIL</code> - Activity observed from CloudTrail logs</p></li>
    /// <li>
    /// <p><code>S3_DATA_EVENTS</code> - Activity observed from CloudTrail data events for Amazon Simple Storage Service (S3). Activities associated with this type will show up only when you have enabled GuardDuty S3 Protection feature in your account. For more information about S3 Protection and the steps to enable it, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html">S3 Protection</a> in the <i>Amazon GuardDuty User Guide</i>.</p></li>
    /// </ul>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the signal used to identify an attack sequence.</p>
    /// <p>Signals can be GuardDuty findings or activities observed in data sources that GuardDuty monitors. For more information, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html">GuardDuty foundational data sources</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    /// <p>A signal type can be one of the following values. Here are the related descriptions:</p>
    /// <ul>
    /// <li>
    /// <p><code>FINDING</code> - Individually generated GuardDuty finding.</p></li>
    /// <li>
    /// <p><code>CLOUD_TRAIL</code> - Activity observed from CloudTrail logs</p></li>
    /// <li>
    /// <p><code>S3_DATA_EVENTS</code> - Activity observed from CloudTrail data events for Amazon Simple Storage Service (S3). Activities associated with this type will show up only when you have enabled GuardDuty S3 Protection feature in your account. For more information about S3 Protection and the steps to enable it, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html">S3 Protection</a> in the <i>Amazon GuardDuty User Guide</i>.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the signal used to identify an attack sequence.</p>
    /// <p>Signals can be GuardDuty findings or activities observed in data sources that GuardDuty monitors. For more information, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html">GuardDuty foundational data sources</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    /// <p>A signal type can be one of the following values. Here are the related descriptions:</p>
    /// <ul>
    /// <li>
    /// <p><code>FINDING</code> - Individually generated GuardDuty finding.</p></li>
    /// <li>
    /// <p><code>CLOUD_TRAIL</code> - Activity observed from CloudTrail logs</p></li>
    /// <li>
    /// <p><code>S3_DATA_EVENTS</code> - Activity observed from CloudTrail data events for Amazon Simple Storage Service (S3). Activities associated with this type will show up only when you have enabled GuardDuty S3 Protection feature in your account. For more information about S3 Protection and the steps to enable it, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html">S3 Protection</a> in the <i>Amazon GuardDuty User Guide</i>.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The identifier of the signal.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the signal.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the signal.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The description of the GuardDuty finding.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the GuardDuty finding.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The description of the GuardDuty finding.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The Amazon Resource Name (ARN) of the product that generated the signal.</p>
    pub fn product_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the product that generated the signal.</p>
    pub fn set_product_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the product that generated the signal.</p>
    pub fn get_product_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_arn
    }
    /// Appends an item to `resource_ids`.
    ///
    /// To override the contents of this collection use [`set_resource_ids`](Self::set_resource_ids).
    ///
    /// <p>The ARN or ID of the Amazon Web Services resource associated with the signal.</p>
    pub fn resource_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.resource_ids.unwrap_or_default();
        v.push(input.into());
        self.resource_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARN or ID of the Amazon Web Services resource associated with the signal.</p>
    pub fn set_resource_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.resource_ids = input;
        self
    }
    /// <p>The ARN or ID of the Amazon Web Services resource associated with the signal.</p>
    pub fn get_resource_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.resource_ids
    }
    /// Appends an item to `signal_indicators`.
    ///
    /// To override the contents of this collection use [`set_signal_indicators`](Self::set_signal_indicators).
    ///
    /// <p>Contains information about the indicators associated with the signals in this attack sequence finding. The values for <code>SignalIndicators</code> are a subset of the values for <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Sequence.html">SequenceIndicators</a>, but the values for these fields don't always match 1:1.</p>
    pub fn signal_indicators(mut self, input: crate::types::Indicator) -> Self {
        let mut v = self.signal_indicators.unwrap_or_default();
        v.push(input);
        self.signal_indicators = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains information about the indicators associated with the signals in this attack sequence finding. The values for <code>SignalIndicators</code> are a subset of the values for <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Sequence.html">SequenceIndicators</a>, but the values for these fields don't always match 1:1.</p>
    pub fn set_signal_indicators(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Indicator>>) -> Self {
        self.signal_indicators = input;
        self
    }
    /// <p>Contains information about the indicators associated with the signals in this attack sequence finding. The values for <code>SignalIndicators</code> are a subset of the values for <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Sequence.html">SequenceIndicators</a>, but the values for these fields don't always match 1:1.</p>
    pub fn get_signal_indicators(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Indicator>> {
        &self.signal_indicators
    }
    /// <p>The name of the GuardDuty signal. For example, when signal type is <code>FINDING</code>, the signal name is the name of the finding.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the GuardDuty signal. For example, when signal type is <code>FINDING</code>, the signal name is the name of the finding.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the GuardDuty signal. For example, when signal type is <code>FINDING</code>, the signal name is the name of the finding.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub fn created_at(mut self, input: i64) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<i64>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<i64> {
        &self.created_at
    }
    /// <p>The timestamp when this signal was last observed.</p>
    pub fn updated_at(mut self, input: i64) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when this signal was last observed.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<i64>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The timestamp when this signal was last observed.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<i64> {
        &self.updated_at
    }
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub fn first_seen_at(mut self, input: i64) -> Self {
        self.first_seen_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub fn set_first_seen_at(mut self, input: ::std::option::Option<i64>) -> Self {
        self.first_seen_at = input;
        self
    }
    /// <p>The timestamp when the first finding or activity related to this signal was observed.</p>
    pub fn get_first_seen_at(&self) -> &::std::option::Option<i64> {
        &self.first_seen_at
    }
    /// <p>The timestamp when the last finding or activity related to this signal was observed.</p>
    pub fn last_seen_at(mut self, input: i64) -> Self {
        self.last_seen_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the last finding or activity related to this signal was observed.</p>
    pub fn set_last_seen_at(mut self, input: ::std::option::Option<i64>) -> Self {
        self.last_seen_at = input;
        self
    }
    /// <p>The timestamp when the last finding or activity related to this signal was observed.</p>
    pub fn get_last_seen_at(&self) -> &::std::option::Option<i64> {
        &self.last_seen_at
    }
    /// <p>The severity associated with the signal. For more information about severity, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html">Severity levels for GuardDuty findings</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    pub fn severity(mut self, input: f64) -> Self {
        self.severity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The severity associated with the signal. For more information about severity, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html">Severity levels for GuardDuty findings</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    pub fn set_severity(mut self, input: ::std::option::Option<f64>) -> Self {
        self.severity = input;
        self
    }
    /// <p>The severity associated with the signal. For more information about severity, see <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html">Severity levels for GuardDuty findings</a> in the <i>Amazon GuardDuty User Guide</i>.</p>
    pub fn get_severity(&self) -> &::std::option::Option<f64> {
        &self.severity
    }
    /// <p>The number of times this signal was observed.</p>
    pub fn count(mut self, input: i32) -> Self {
        self.count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of times this signal was observed.</p>
    pub fn set_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.count = input;
        self
    }
    /// <p>The number of times this signal was observed.</p>
    pub fn get_count(&self) -> &::std::option::Option<i32> {
        &self.count
    }
    /// Appends an item to `actor_ids`.
    ///
    /// To override the contents of this collection use [`set_actor_ids`](Self::set_actor_ids).
    ///
    /// <p>The IDs of the threat actors involved in the signal.</p>
    pub fn actor_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.actor_ids.unwrap_or_default();
        v.push(input.into());
        self.actor_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the threat actors involved in the signal.</p>
    pub fn set_actor_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.actor_ids = input;
        self
    }
    /// <p>The IDs of the threat actors involved in the signal.</p>
    pub fn get_actor_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.actor_ids
    }
    /// Appends an item to `endpoint_ids`.
    ///
    /// To override the contents of this collection use [`set_endpoint_ids`](Self::set_endpoint_ids).
    ///
    /// <p>Information about the endpoint IDs associated with this signal.</p>
    pub fn endpoint_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.endpoint_ids.unwrap_or_default();
        v.push(input.into());
        self.endpoint_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the endpoint IDs associated with this signal.</p>
    pub fn set_endpoint_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.endpoint_ids = input;
        self
    }
    /// <p>Information about the endpoint IDs associated with this signal.</p>
    pub fn get_endpoint_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.endpoint_ids
    }
    /// Consumes the builder and constructs a [`Signal`](crate::types::Signal).
    pub fn build(self) -> crate::types::Signal {
        crate::types::Signal {
            r#type: self.r#type,
            id: self.id,
            title: self.title,
            product_arn: self.product_arn,
            resource_ids: self.resource_ids,
            signal_indicators: self.signal_indicators,
            name: self.name,
            created_at: self.created_at,
            updated_at: self.updated_at,
            first_seen_at: self.first_seen_at,
            last_seen_at: self.last_seen_at,
            severity: self.severity,
            count: self.count,
            actor_ids: self.actor_ids,
            endpoint_ids: self.endpoint_ids,
        }
    }
}
