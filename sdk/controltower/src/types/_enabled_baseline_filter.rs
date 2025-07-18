// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A filter applied on the <code>ListEnabledBaseline</code> operation. Allowed filters are <code>baselineIdentifiers</code> and <code>targetIdentifiers</code>. The filter can be applied for either, or both.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnabledBaselineFilter {
    /// <p>Identifiers for the targets of the <code>Baseline</code> filter operation.</p>
    pub target_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Identifiers for the <code>Baseline</code> objects returned as part of the filter operation.</p>
    pub baseline_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An optional filter that sets up a list of <code>parentIdentifiers</code> to filter the results of the <code>ListEnabledBaseline</code> output.</p>
    pub parent_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of <code>EnablementStatus</code> items.</p>
    pub statuses: ::std::option::Option<::std::vec::Vec<crate::types::EnablementStatus>>,
    /// <p>A list of <code>EnabledBaselineDriftStatus</code> items for enabled baselines.</p>
    pub inheritance_drift_statuses: ::std::option::Option<::std::vec::Vec<crate::types::EnabledBaselineDriftStatus>>,
}
impl EnabledBaselineFilter {
    /// <p>Identifiers for the targets of the <code>Baseline</code> filter operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.target_identifiers.is_none()`.
    pub fn target_identifiers(&self) -> &[::std::string::String] {
        self.target_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>Identifiers for the <code>Baseline</code> objects returned as part of the filter operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.baseline_identifiers.is_none()`.
    pub fn baseline_identifiers(&self) -> &[::std::string::String] {
        self.baseline_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>An optional filter that sets up a list of <code>parentIdentifiers</code> to filter the results of the <code>ListEnabledBaseline</code> output.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parent_identifiers.is_none()`.
    pub fn parent_identifiers(&self) -> &[::std::string::String] {
        self.parent_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>A list of <code>EnablementStatus</code> items.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.statuses.is_none()`.
    pub fn statuses(&self) -> &[crate::types::EnablementStatus] {
        self.statuses.as_deref().unwrap_or_default()
    }
    /// <p>A list of <code>EnabledBaselineDriftStatus</code> items for enabled baselines.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.inheritance_drift_statuses.is_none()`.
    pub fn inheritance_drift_statuses(&self) -> &[crate::types::EnabledBaselineDriftStatus] {
        self.inheritance_drift_statuses.as_deref().unwrap_or_default()
    }
}
impl EnabledBaselineFilter {
    /// Creates a new builder-style object to manufacture [`EnabledBaselineFilter`](crate::types::EnabledBaselineFilter).
    pub fn builder() -> crate::types::builders::EnabledBaselineFilterBuilder {
        crate::types::builders::EnabledBaselineFilterBuilder::default()
    }
}

/// A builder for [`EnabledBaselineFilter`](crate::types::EnabledBaselineFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnabledBaselineFilterBuilder {
    pub(crate) target_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) baseline_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) parent_identifiers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) statuses: ::std::option::Option<::std::vec::Vec<crate::types::EnablementStatus>>,
    pub(crate) inheritance_drift_statuses: ::std::option::Option<::std::vec::Vec<crate::types::EnabledBaselineDriftStatus>>,
}
impl EnabledBaselineFilterBuilder {
    /// Appends an item to `target_identifiers`.
    ///
    /// To override the contents of this collection use [`set_target_identifiers`](Self::set_target_identifiers).
    ///
    /// <p>Identifiers for the targets of the <code>Baseline</code> filter operation.</p>
    pub fn target_identifiers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.target_identifiers.unwrap_or_default();
        v.push(input.into());
        self.target_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>Identifiers for the targets of the <code>Baseline</code> filter operation.</p>
    pub fn set_target_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.target_identifiers = input;
        self
    }
    /// <p>Identifiers for the targets of the <code>Baseline</code> filter operation.</p>
    pub fn get_target_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.target_identifiers
    }
    /// Appends an item to `baseline_identifiers`.
    ///
    /// To override the contents of this collection use [`set_baseline_identifiers`](Self::set_baseline_identifiers).
    ///
    /// <p>Identifiers for the <code>Baseline</code> objects returned as part of the filter operation.</p>
    pub fn baseline_identifiers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.baseline_identifiers.unwrap_or_default();
        v.push(input.into());
        self.baseline_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>Identifiers for the <code>Baseline</code> objects returned as part of the filter operation.</p>
    pub fn set_baseline_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.baseline_identifiers = input;
        self
    }
    /// <p>Identifiers for the <code>Baseline</code> objects returned as part of the filter operation.</p>
    pub fn get_baseline_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.baseline_identifiers
    }
    /// Appends an item to `parent_identifiers`.
    ///
    /// To override the contents of this collection use [`set_parent_identifiers`](Self::set_parent_identifiers).
    ///
    /// <p>An optional filter that sets up a list of <code>parentIdentifiers</code> to filter the results of the <code>ListEnabledBaseline</code> output.</p>
    pub fn parent_identifiers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.parent_identifiers.unwrap_or_default();
        v.push(input.into());
        self.parent_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>An optional filter that sets up a list of <code>parentIdentifiers</code> to filter the results of the <code>ListEnabledBaseline</code> output.</p>
    pub fn set_parent_identifiers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.parent_identifiers = input;
        self
    }
    /// <p>An optional filter that sets up a list of <code>parentIdentifiers</code> to filter the results of the <code>ListEnabledBaseline</code> output.</p>
    pub fn get_parent_identifiers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.parent_identifiers
    }
    /// Appends an item to `statuses`.
    ///
    /// To override the contents of this collection use [`set_statuses`](Self::set_statuses).
    ///
    /// <p>A list of <code>EnablementStatus</code> items.</p>
    pub fn statuses(mut self, input: crate::types::EnablementStatus) -> Self {
        let mut v = self.statuses.unwrap_or_default();
        v.push(input);
        self.statuses = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>EnablementStatus</code> items.</p>
    pub fn set_statuses(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EnablementStatus>>) -> Self {
        self.statuses = input;
        self
    }
    /// <p>A list of <code>EnablementStatus</code> items.</p>
    pub fn get_statuses(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EnablementStatus>> {
        &self.statuses
    }
    /// Appends an item to `inheritance_drift_statuses`.
    ///
    /// To override the contents of this collection use [`set_inheritance_drift_statuses`](Self::set_inheritance_drift_statuses).
    ///
    /// <p>A list of <code>EnabledBaselineDriftStatus</code> items for enabled baselines.</p>
    pub fn inheritance_drift_statuses(mut self, input: crate::types::EnabledBaselineDriftStatus) -> Self {
        let mut v = self.inheritance_drift_statuses.unwrap_or_default();
        v.push(input);
        self.inheritance_drift_statuses = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>EnabledBaselineDriftStatus</code> items for enabled baselines.</p>
    pub fn set_inheritance_drift_statuses(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EnabledBaselineDriftStatus>>) -> Self {
        self.inheritance_drift_statuses = input;
        self
    }
    /// <p>A list of <code>EnabledBaselineDriftStatus</code> items for enabled baselines.</p>
    pub fn get_inheritance_drift_statuses(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EnabledBaselineDriftStatus>> {
        &self.inheritance_drift_statuses
    }
    /// Consumes the builder and constructs a [`EnabledBaselineFilter`](crate::types::EnabledBaselineFilter).
    pub fn build(self) -> crate::types::EnabledBaselineFilter {
        crate::types::EnabledBaselineFilter {
            target_identifiers: self.target_identifiers,
            baseline_identifiers: self.baseline_identifiers,
            parent_identifiers: self.parent_identifiers,
            statuses: self.statuses,
            inheritance_drift_statuses: self.inheritance_drift_statuses,
        }
    }
}
