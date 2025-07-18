// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies details of the scheduled Auto-Tune action. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScheduledAutoTuneDetails {
    /// <p>Specifies timestamp for the Auto-Tune action scheduled for the domain.</p>
    pub date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Specifies Auto-Tune action type. Valid values are JVM_HEAP_SIZE_TUNING and JVM_YOUNG_GEN_TUNING.</p>
    pub action_type: ::std::option::Option<crate::types::ScheduledAutoTuneActionType>,
    /// <p>Specifies Auto-Tune action description.</p>
    pub action: ::std::option::Option<::std::string::String>,
    /// <p>Specifies Auto-Tune action severity. Valid values are LOW, MEDIUM and HIGH.</p>
    pub severity: ::std::option::Option<crate::types::ScheduledAutoTuneSeverityType>,
}
impl ScheduledAutoTuneDetails {
    /// <p>Specifies timestamp for the Auto-Tune action scheduled for the domain.</p>
    pub fn date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.date.as_ref()
    }
    /// <p>Specifies Auto-Tune action type. Valid values are JVM_HEAP_SIZE_TUNING and JVM_YOUNG_GEN_TUNING.</p>
    pub fn action_type(&self) -> ::std::option::Option<&crate::types::ScheduledAutoTuneActionType> {
        self.action_type.as_ref()
    }
    /// <p>Specifies Auto-Tune action description.</p>
    pub fn action(&self) -> ::std::option::Option<&str> {
        self.action.as_deref()
    }
    /// <p>Specifies Auto-Tune action severity. Valid values are LOW, MEDIUM and HIGH.</p>
    pub fn severity(&self) -> ::std::option::Option<&crate::types::ScheduledAutoTuneSeverityType> {
        self.severity.as_ref()
    }
}
impl ScheduledAutoTuneDetails {
    /// Creates a new builder-style object to manufacture [`ScheduledAutoTuneDetails`](crate::types::ScheduledAutoTuneDetails).
    pub fn builder() -> crate::types::builders::ScheduledAutoTuneDetailsBuilder {
        crate::types::builders::ScheduledAutoTuneDetailsBuilder::default()
    }
}

/// A builder for [`ScheduledAutoTuneDetails`](crate::types::ScheduledAutoTuneDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScheduledAutoTuneDetailsBuilder {
    pub(crate) date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) action_type: ::std::option::Option<crate::types::ScheduledAutoTuneActionType>,
    pub(crate) action: ::std::option::Option<::std::string::String>,
    pub(crate) severity: ::std::option::Option<crate::types::ScheduledAutoTuneSeverityType>,
}
impl ScheduledAutoTuneDetailsBuilder {
    /// <p>Specifies timestamp for the Auto-Tune action scheduled for the domain.</p>
    pub fn date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies timestamp for the Auto-Tune action scheduled for the domain.</p>
    pub fn set_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.date = input;
        self
    }
    /// <p>Specifies timestamp for the Auto-Tune action scheduled for the domain.</p>
    pub fn get_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.date
    }
    /// <p>Specifies Auto-Tune action type. Valid values are JVM_HEAP_SIZE_TUNING and JVM_YOUNG_GEN_TUNING.</p>
    pub fn action_type(mut self, input: crate::types::ScheduledAutoTuneActionType) -> Self {
        self.action_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies Auto-Tune action type. Valid values are JVM_HEAP_SIZE_TUNING and JVM_YOUNG_GEN_TUNING.</p>
    pub fn set_action_type(mut self, input: ::std::option::Option<crate::types::ScheduledAutoTuneActionType>) -> Self {
        self.action_type = input;
        self
    }
    /// <p>Specifies Auto-Tune action type. Valid values are JVM_HEAP_SIZE_TUNING and JVM_YOUNG_GEN_TUNING.</p>
    pub fn get_action_type(&self) -> &::std::option::Option<crate::types::ScheduledAutoTuneActionType> {
        &self.action_type
    }
    /// <p>Specifies Auto-Tune action description.</p>
    pub fn action(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies Auto-Tune action description.</p>
    pub fn set_action(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action = input;
        self
    }
    /// <p>Specifies Auto-Tune action description.</p>
    pub fn get_action(&self) -> &::std::option::Option<::std::string::String> {
        &self.action
    }
    /// <p>Specifies Auto-Tune action severity. Valid values are LOW, MEDIUM and HIGH.</p>
    pub fn severity(mut self, input: crate::types::ScheduledAutoTuneSeverityType) -> Self {
        self.severity = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies Auto-Tune action severity. Valid values are LOW, MEDIUM and HIGH.</p>
    pub fn set_severity(mut self, input: ::std::option::Option<crate::types::ScheduledAutoTuneSeverityType>) -> Self {
        self.severity = input;
        self
    }
    /// <p>Specifies Auto-Tune action severity. Valid values are LOW, MEDIUM and HIGH.</p>
    pub fn get_severity(&self) -> &::std::option::Option<crate::types::ScheduledAutoTuneSeverityType> {
        &self.severity
    }
    /// Consumes the builder and constructs a [`ScheduledAutoTuneDetails`](crate::types::ScheduledAutoTuneDetails).
    pub fn build(self) -> crate::types::ScheduledAutoTuneDetails {
        crate::types::ScheduledAutoTuneDetails {
            date: self.date,
            action_type: self.action_type,
            action: self.action,
            severity: self.severity,
        }
    }
}
