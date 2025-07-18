// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a health event created in a monitor in Amazon CloudWatch Internet Monitor.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HealthEvent {
    /// <p>The Amazon Resource Name (ARN) of the event.</p>
    pub event_arn: ::std::string::String,
    /// <p>The internally-generated identifier of a specific network traffic impairment health event.</p>
    pub event_id: ::std::string::String,
    /// <p>When a health event started.</p>
    pub started_at: ::aws_smithy_types::DateTime,
    /// <p>The time when a health event ended. If the health event is still active, then the end time is not set.</p>
    pub ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>When the health event was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>When the health event was last updated.</p>
    pub last_updated_at: ::aws_smithy_types::DateTime,
    /// <p>The locations impacted by the health event.</p>
    pub impacted_locations: ::std::vec::Vec<crate::types::ImpactedLocation>,
    /// <p>The status of a health event.</p>
    pub status: crate::types::HealthEventStatus,
    /// <p>The impact on total traffic that a health event has, in increased latency or reduced availability. This is the percentage of how much latency has increased or availability has decreased during the event, compared to what is typical for traffic from this client location to the Amazon Web Services location using this client network.</p>
    pub percent_of_total_traffic_impacted: ::std::option::Option<f64>,
    /// <p>The type of impairment for a health event.</p>
    pub impact_type: crate::types::HealthEventImpactType,
    /// <p>The value of the threshold percentage for performance or availability that was configured when Amazon CloudWatch Internet Monitor created the health event.</p>
    pub health_score_threshold: f64,
}
impl HealthEvent {
    /// <p>The Amazon Resource Name (ARN) of the event.</p>
    pub fn event_arn(&self) -> &str {
        use std::ops::Deref;
        self.event_arn.deref()
    }
    /// <p>The internally-generated identifier of a specific network traffic impairment health event.</p>
    pub fn event_id(&self) -> &str {
        use std::ops::Deref;
        self.event_id.deref()
    }
    /// <p>When a health event started.</p>
    pub fn started_at(&self) -> &::aws_smithy_types::DateTime {
        &self.started_at
    }
    /// <p>The time when a health event ended. If the health event is still active, then the end time is not set.</p>
    pub fn ended_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.ended_at.as_ref()
    }
    /// <p>When the health event was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>When the health event was last updated.</p>
    pub fn last_updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.last_updated_at
    }
    /// <p>The locations impacted by the health event.</p>
    pub fn impacted_locations(&self) -> &[crate::types::ImpactedLocation] {
        use std::ops::Deref;
        self.impacted_locations.deref()
    }
    /// <p>The status of a health event.</p>
    pub fn status(&self) -> &crate::types::HealthEventStatus {
        &self.status
    }
    /// <p>The impact on total traffic that a health event has, in increased latency or reduced availability. This is the percentage of how much latency has increased or availability has decreased during the event, compared to what is typical for traffic from this client location to the Amazon Web Services location using this client network.</p>
    pub fn percent_of_total_traffic_impacted(&self) -> ::std::option::Option<f64> {
        self.percent_of_total_traffic_impacted
    }
    /// <p>The type of impairment for a health event.</p>
    pub fn impact_type(&self) -> &crate::types::HealthEventImpactType {
        &self.impact_type
    }
    /// <p>The value of the threshold percentage for performance or availability that was configured when Amazon CloudWatch Internet Monitor created the health event.</p>
    pub fn health_score_threshold(&self) -> f64 {
        self.health_score_threshold
    }
}
impl HealthEvent {
    /// Creates a new builder-style object to manufacture [`HealthEvent`](crate::types::HealthEvent).
    pub fn builder() -> crate::types::builders::HealthEventBuilder {
        crate::types::builders::HealthEventBuilder::default()
    }
}

/// A builder for [`HealthEvent`](crate::types::HealthEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HealthEventBuilder {
    pub(crate) event_arn: ::std::option::Option<::std::string::String>,
    pub(crate) event_id: ::std::option::Option<::std::string::String>,
    pub(crate) started_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) impacted_locations: ::std::option::Option<::std::vec::Vec<crate::types::ImpactedLocation>>,
    pub(crate) status: ::std::option::Option<crate::types::HealthEventStatus>,
    pub(crate) percent_of_total_traffic_impacted: ::std::option::Option<f64>,
    pub(crate) impact_type: ::std::option::Option<crate::types::HealthEventImpactType>,
    pub(crate) health_score_threshold: ::std::option::Option<f64>,
}
impl HealthEventBuilder {
    /// <p>The Amazon Resource Name (ARN) of the event.</p>
    /// This field is required.
    pub fn event_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the event.</p>
    pub fn set_event_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the event.</p>
    pub fn get_event_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_arn
    }
    /// <p>The internally-generated identifier of a specific network traffic impairment health event.</p>
    /// This field is required.
    pub fn event_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The internally-generated identifier of a specific network traffic impairment health event.</p>
    pub fn set_event_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_id = input;
        self
    }
    /// <p>The internally-generated identifier of a specific network traffic impairment health event.</p>
    pub fn get_event_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_id
    }
    /// <p>When a health event started.</p>
    /// This field is required.
    pub fn started_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.started_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>When a health event started.</p>
    pub fn set_started_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.started_at = input;
        self
    }
    /// <p>When a health event started.</p>
    pub fn get_started_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.started_at
    }
    /// <p>The time when a health event ended. If the health event is still active, then the end time is not set.</p>
    pub fn ended_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.ended_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when a health event ended. If the health event is still active, then the end time is not set.</p>
    pub fn set_ended_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.ended_at = input;
        self
    }
    /// <p>The time when a health event ended. If the health event is still active, then the end time is not set.</p>
    pub fn get_ended_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.ended_at
    }
    /// <p>When the health event was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the health event was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>When the health event was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>When the health event was last updated.</p>
    /// This field is required.
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the health event was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>When the health event was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// Appends an item to `impacted_locations`.
    ///
    /// To override the contents of this collection use [`set_impacted_locations`](Self::set_impacted_locations).
    ///
    /// <p>The locations impacted by the health event.</p>
    pub fn impacted_locations(mut self, input: crate::types::ImpactedLocation) -> Self {
        let mut v = self.impacted_locations.unwrap_or_default();
        v.push(input);
        self.impacted_locations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The locations impacted by the health event.</p>
    pub fn set_impacted_locations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ImpactedLocation>>) -> Self {
        self.impacted_locations = input;
        self
    }
    /// <p>The locations impacted by the health event.</p>
    pub fn get_impacted_locations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ImpactedLocation>> {
        &self.impacted_locations
    }
    /// <p>The status of a health event.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::HealthEventStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a health event.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::HealthEventStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of a health event.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::HealthEventStatus> {
        &self.status
    }
    /// <p>The impact on total traffic that a health event has, in increased latency or reduced availability. This is the percentage of how much latency has increased or availability has decreased during the event, compared to what is typical for traffic from this client location to the Amazon Web Services location using this client network.</p>
    pub fn percent_of_total_traffic_impacted(mut self, input: f64) -> Self {
        self.percent_of_total_traffic_impacted = ::std::option::Option::Some(input);
        self
    }
    /// <p>The impact on total traffic that a health event has, in increased latency or reduced availability. This is the percentage of how much latency has increased or availability has decreased during the event, compared to what is typical for traffic from this client location to the Amazon Web Services location using this client network.</p>
    pub fn set_percent_of_total_traffic_impacted(mut self, input: ::std::option::Option<f64>) -> Self {
        self.percent_of_total_traffic_impacted = input;
        self
    }
    /// <p>The impact on total traffic that a health event has, in increased latency or reduced availability. This is the percentage of how much latency has increased or availability has decreased during the event, compared to what is typical for traffic from this client location to the Amazon Web Services location using this client network.</p>
    pub fn get_percent_of_total_traffic_impacted(&self) -> &::std::option::Option<f64> {
        &self.percent_of_total_traffic_impacted
    }
    /// <p>The type of impairment for a health event.</p>
    /// This field is required.
    pub fn impact_type(mut self, input: crate::types::HealthEventImpactType) -> Self {
        self.impact_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of impairment for a health event.</p>
    pub fn set_impact_type(mut self, input: ::std::option::Option<crate::types::HealthEventImpactType>) -> Self {
        self.impact_type = input;
        self
    }
    /// <p>The type of impairment for a health event.</p>
    pub fn get_impact_type(&self) -> &::std::option::Option<crate::types::HealthEventImpactType> {
        &self.impact_type
    }
    /// <p>The value of the threshold percentage for performance or availability that was configured when Amazon CloudWatch Internet Monitor created the health event.</p>
    pub fn health_score_threshold(mut self, input: f64) -> Self {
        self.health_score_threshold = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of the threshold percentage for performance or availability that was configured when Amazon CloudWatch Internet Monitor created the health event.</p>
    pub fn set_health_score_threshold(mut self, input: ::std::option::Option<f64>) -> Self {
        self.health_score_threshold = input;
        self
    }
    /// <p>The value of the threshold percentage for performance or availability that was configured when Amazon CloudWatch Internet Monitor created the health event.</p>
    pub fn get_health_score_threshold(&self) -> &::std::option::Option<f64> {
        &self.health_score_threshold
    }
    /// Consumes the builder and constructs a [`HealthEvent`](crate::types::HealthEvent).
    /// This method will fail if any of the following fields are not set:
    /// - [`event_arn`](crate::types::builders::HealthEventBuilder::event_arn)
    /// - [`event_id`](crate::types::builders::HealthEventBuilder::event_id)
    /// - [`started_at`](crate::types::builders::HealthEventBuilder::started_at)
    /// - [`last_updated_at`](crate::types::builders::HealthEventBuilder::last_updated_at)
    /// - [`impacted_locations`](crate::types::builders::HealthEventBuilder::impacted_locations)
    /// - [`status`](crate::types::builders::HealthEventBuilder::status)
    /// - [`impact_type`](crate::types::builders::HealthEventBuilder::impact_type)
    pub fn build(self) -> ::std::result::Result<crate::types::HealthEvent, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::HealthEvent {
            event_arn: self.event_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "event_arn",
                    "event_arn was not specified but it is required when building HealthEvent",
                )
            })?,
            event_id: self.event_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "event_id",
                    "event_id was not specified but it is required when building HealthEvent",
                )
            })?,
            started_at: self.started_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "started_at",
                    "started_at was not specified but it is required when building HealthEvent",
                )
            })?,
            ended_at: self.ended_at,
            created_at: self.created_at,
            last_updated_at: self.last_updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_updated_at",
                    "last_updated_at was not specified but it is required when building HealthEvent",
                )
            })?,
            impacted_locations: self.impacted_locations.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "impacted_locations",
                    "impacted_locations was not specified but it is required when building HealthEvent",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building HealthEvent",
                )
            })?,
            percent_of_total_traffic_impacted: self.percent_of_total_traffic_impacted,
            impact_type: self.impact_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "impact_type",
                    "impact_type was not specified but it is required when building HealthEvent",
                )
            })?,
            health_score_threshold: self.health_score_threshold.unwrap_or_default(),
        })
    }
}
