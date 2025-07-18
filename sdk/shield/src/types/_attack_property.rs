// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details of a Shield event. This is provided as part of an <code>AttackDetail</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AttackProperty {
    /// <p>The type of Shield event that was observed. <code>NETWORK</code> indicates layer 3 and layer 4 events and <code>APPLICATION</code> indicates layer 7 events.</p>
    /// <p>For infrastructure layer events (L3 and L4 events), you can view metrics for top contributors in Amazon CloudWatch metrics. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#set-ddos-alarms">Shield metrics and alarms</a> in the <i>WAF Developer Guide</i>.</p>
    pub attack_layer: ::std::option::Option<crate::types::AttackLayer>,
    /// <p>Defines the Shield event property information that is provided. The <code>WORDPRESS_PINGBACK_REFLECTOR</code> and <code>WORDPRESS_PINGBACK_SOURCE</code> values are valid only for WordPress reflective pingback events.</p>
    pub attack_property_identifier: ::std::option::Option<crate::types::AttackPropertyIdentifier>,
    /// <p>Contributor objects for the top five contributors to a Shield event. A contributor is a source of traffic that Shield Advanced identifies as responsible for some or all of an event.</p>
    pub top_contributors: ::std::option::Option<::std::vec::Vec<crate::types::Contributor>>,
    /// <p>The unit used for the <code>Contributor</code> <code>Value</code> property.</p>
    pub unit: ::std::option::Option<crate::types::Unit>,
    /// <p>The total contributions made to this Shield event by all contributors.</p>
    pub total: i64,
}
impl AttackProperty {
    /// <p>The type of Shield event that was observed. <code>NETWORK</code> indicates layer 3 and layer 4 events and <code>APPLICATION</code> indicates layer 7 events.</p>
    /// <p>For infrastructure layer events (L3 and L4 events), you can view metrics for top contributors in Amazon CloudWatch metrics. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#set-ddos-alarms">Shield metrics and alarms</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn attack_layer(&self) -> ::std::option::Option<&crate::types::AttackLayer> {
        self.attack_layer.as_ref()
    }
    /// <p>Defines the Shield event property information that is provided. The <code>WORDPRESS_PINGBACK_REFLECTOR</code> and <code>WORDPRESS_PINGBACK_SOURCE</code> values are valid only for WordPress reflective pingback events.</p>
    pub fn attack_property_identifier(&self) -> ::std::option::Option<&crate::types::AttackPropertyIdentifier> {
        self.attack_property_identifier.as_ref()
    }
    /// <p>Contributor objects for the top five contributors to a Shield event. A contributor is a source of traffic that Shield Advanced identifies as responsible for some or all of an event.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.top_contributors.is_none()`.
    pub fn top_contributors(&self) -> &[crate::types::Contributor] {
        self.top_contributors.as_deref().unwrap_or_default()
    }
    /// <p>The unit used for the <code>Contributor</code> <code>Value</code> property.</p>
    pub fn unit(&self) -> ::std::option::Option<&crate::types::Unit> {
        self.unit.as_ref()
    }
    /// <p>The total contributions made to this Shield event by all contributors.</p>
    pub fn total(&self) -> i64 {
        self.total
    }
}
impl AttackProperty {
    /// Creates a new builder-style object to manufacture [`AttackProperty`](crate::types::AttackProperty).
    pub fn builder() -> crate::types::builders::AttackPropertyBuilder {
        crate::types::builders::AttackPropertyBuilder::default()
    }
}

/// A builder for [`AttackProperty`](crate::types::AttackProperty).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AttackPropertyBuilder {
    pub(crate) attack_layer: ::std::option::Option<crate::types::AttackLayer>,
    pub(crate) attack_property_identifier: ::std::option::Option<crate::types::AttackPropertyIdentifier>,
    pub(crate) top_contributors: ::std::option::Option<::std::vec::Vec<crate::types::Contributor>>,
    pub(crate) unit: ::std::option::Option<crate::types::Unit>,
    pub(crate) total: ::std::option::Option<i64>,
}
impl AttackPropertyBuilder {
    /// <p>The type of Shield event that was observed. <code>NETWORK</code> indicates layer 3 and layer 4 events and <code>APPLICATION</code> indicates layer 7 events.</p>
    /// <p>For infrastructure layer events (L3 and L4 events), you can view metrics for top contributors in Amazon CloudWatch metrics. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#set-ddos-alarms">Shield metrics and alarms</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn attack_layer(mut self, input: crate::types::AttackLayer) -> Self {
        self.attack_layer = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of Shield event that was observed. <code>NETWORK</code> indicates layer 3 and layer 4 events and <code>APPLICATION</code> indicates layer 7 events.</p>
    /// <p>For infrastructure layer events (L3 and L4 events), you can view metrics for top contributors in Amazon CloudWatch metrics. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#set-ddos-alarms">Shield metrics and alarms</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn set_attack_layer(mut self, input: ::std::option::Option<crate::types::AttackLayer>) -> Self {
        self.attack_layer = input;
        self
    }
    /// <p>The type of Shield event that was observed. <code>NETWORK</code> indicates layer 3 and layer 4 events and <code>APPLICATION</code> indicates layer 7 events.</p>
    /// <p>For infrastructure layer events (L3 and L4 events), you can view metrics for top contributors in Amazon CloudWatch metrics. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#set-ddos-alarms">Shield metrics and alarms</a> in the <i>WAF Developer Guide</i>.</p>
    pub fn get_attack_layer(&self) -> &::std::option::Option<crate::types::AttackLayer> {
        &self.attack_layer
    }
    /// <p>Defines the Shield event property information that is provided. The <code>WORDPRESS_PINGBACK_REFLECTOR</code> and <code>WORDPRESS_PINGBACK_SOURCE</code> values are valid only for WordPress reflective pingback events.</p>
    pub fn attack_property_identifier(mut self, input: crate::types::AttackPropertyIdentifier) -> Self {
        self.attack_property_identifier = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the Shield event property information that is provided. The <code>WORDPRESS_PINGBACK_REFLECTOR</code> and <code>WORDPRESS_PINGBACK_SOURCE</code> values are valid only for WordPress reflective pingback events.</p>
    pub fn set_attack_property_identifier(mut self, input: ::std::option::Option<crate::types::AttackPropertyIdentifier>) -> Self {
        self.attack_property_identifier = input;
        self
    }
    /// <p>Defines the Shield event property information that is provided. The <code>WORDPRESS_PINGBACK_REFLECTOR</code> and <code>WORDPRESS_PINGBACK_SOURCE</code> values are valid only for WordPress reflective pingback events.</p>
    pub fn get_attack_property_identifier(&self) -> &::std::option::Option<crate::types::AttackPropertyIdentifier> {
        &self.attack_property_identifier
    }
    /// Appends an item to `top_contributors`.
    ///
    /// To override the contents of this collection use [`set_top_contributors`](Self::set_top_contributors).
    ///
    /// <p>Contributor objects for the top five contributors to a Shield event. A contributor is a source of traffic that Shield Advanced identifies as responsible for some or all of an event.</p>
    pub fn top_contributors(mut self, input: crate::types::Contributor) -> Self {
        let mut v = self.top_contributors.unwrap_or_default();
        v.push(input);
        self.top_contributors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contributor objects for the top five contributors to a Shield event. A contributor is a source of traffic that Shield Advanced identifies as responsible for some or all of an event.</p>
    pub fn set_top_contributors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Contributor>>) -> Self {
        self.top_contributors = input;
        self
    }
    /// <p>Contributor objects for the top five contributors to a Shield event. A contributor is a source of traffic that Shield Advanced identifies as responsible for some or all of an event.</p>
    pub fn get_top_contributors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Contributor>> {
        &self.top_contributors
    }
    /// <p>The unit used for the <code>Contributor</code> <code>Value</code> property.</p>
    pub fn unit(mut self, input: crate::types::Unit) -> Self {
        self.unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unit used for the <code>Contributor</code> <code>Value</code> property.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<crate::types::Unit>) -> Self {
        self.unit = input;
        self
    }
    /// <p>The unit used for the <code>Contributor</code> <code>Value</code> property.</p>
    pub fn get_unit(&self) -> &::std::option::Option<crate::types::Unit> {
        &self.unit
    }
    /// <p>The total contributions made to this Shield event by all contributors.</p>
    pub fn total(mut self, input: i64) -> Self {
        self.total = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total contributions made to this Shield event by all contributors.</p>
    pub fn set_total(mut self, input: ::std::option::Option<i64>) -> Self {
        self.total = input;
        self
    }
    /// <p>The total contributions made to this Shield event by all contributors.</p>
    pub fn get_total(&self) -> &::std::option::Option<i64> {
        &self.total
    }
    /// Consumes the builder and constructs a [`AttackProperty`](crate::types::AttackProperty).
    pub fn build(self) -> crate::types::AttackProperty {
        crate::types::AttackProperty {
            attack_layer: self.attack_layer,
            attack_property_identifier: self.attack_property_identifier,
            top_contributors: self.top_contributors,
            unit: self.unit,
            total: self.total.unwrap_or_default(),
        }
    }
}
