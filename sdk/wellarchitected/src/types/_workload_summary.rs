// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A workload summary return object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkloadSummary {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub workload_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN for the workload.</p>
    pub workload_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the workload.</p>
    /// <p>The name must be unique within an account within an Amazon Web Services Region. Spaces and capitalization are ignored when checking for uniqueness.</p>
    pub workload_name: ::std::option::Option<::std::string::String>,
    /// <p>An Amazon Web Services account ID.</p>
    pub owner: ::std::option::Option<::std::string::String>,
    /// <p>The date and time recorded.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The list of lenses associated with the workload. Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    /// <p>If a review template that specifies lenses is applied to the workload, those lenses are applied to the workload in addition to these lenses.</p>
    pub lenses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub risk_counts: ::std::option::Option<::std::collections::HashMap<crate::types::Risk, i32>>,
    /// <p>The improvement status for a workload.</p>
    pub improvement_status: ::std::option::Option<crate::types::WorkloadImprovementStatus>,
    /// <p>Profile associated with a workload.</p>
    pub profiles: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadProfile>>,
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub prioritized_risk_counts: ::std::option::Option<::std::collections::HashMap<crate::types::Risk, i32>>,
}
impl WorkloadSummary {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn workload_id(&self) -> ::std::option::Option<&str> {
        self.workload_id.as_deref()
    }
    /// <p>The ARN for the workload.</p>
    pub fn workload_arn(&self) -> ::std::option::Option<&str> {
        self.workload_arn.as_deref()
    }
    /// <p>The name of the workload.</p>
    /// <p>The name must be unique within an account within an Amazon Web Services Region. Spaces and capitalization are ignored when checking for uniqueness.</p>
    pub fn workload_name(&self) -> ::std::option::Option<&str> {
        self.workload_name.as_deref()
    }
    /// <p>An Amazon Web Services account ID.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
    /// <p>The date and time recorded.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>The list of lenses associated with the workload. Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    /// <p>If a review template that specifies lenses is applied to the workload, those lenses are applied to the workload in addition to these lenses.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.lenses.is_none()`.
    pub fn lenses(&self) -> &[::std::string::String] {
        self.lenses.as_deref().unwrap_or_default()
    }
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub fn risk_counts(&self) -> ::std::option::Option<&::std::collections::HashMap<crate::types::Risk, i32>> {
        self.risk_counts.as_ref()
    }
    /// <p>The improvement status for a workload.</p>
    pub fn improvement_status(&self) -> ::std::option::Option<&crate::types::WorkloadImprovementStatus> {
        self.improvement_status.as_ref()
    }
    /// <p>Profile associated with a workload.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.profiles.is_none()`.
    pub fn profiles(&self) -> &[crate::types::WorkloadProfile] {
        self.profiles.as_deref().unwrap_or_default()
    }
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub fn prioritized_risk_counts(&self) -> ::std::option::Option<&::std::collections::HashMap<crate::types::Risk, i32>> {
        self.prioritized_risk_counts.as_ref()
    }
}
impl WorkloadSummary {
    /// Creates a new builder-style object to manufacture [`WorkloadSummary`](crate::types::WorkloadSummary).
    pub fn builder() -> crate::types::builders::WorkloadSummaryBuilder {
        crate::types::builders::WorkloadSummaryBuilder::default()
    }
}

/// A builder for [`WorkloadSummary`](crate::types::WorkloadSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkloadSummaryBuilder {
    pub(crate) workload_id: ::std::option::Option<::std::string::String>,
    pub(crate) workload_arn: ::std::option::Option<::std::string::String>,
    pub(crate) workload_name: ::std::option::Option<::std::string::String>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) lenses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) risk_counts: ::std::option::Option<::std::collections::HashMap<crate::types::Risk, i32>>,
    pub(crate) improvement_status: ::std::option::Option<crate::types::WorkloadImprovementStatus>,
    pub(crate) profiles: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadProfile>>,
    pub(crate) prioritized_risk_counts: ::std::option::Option<::std::collections::HashMap<crate::types::Risk, i32>>,
}
impl WorkloadSummaryBuilder {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn workload_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workload_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn set_workload_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workload_id = input;
        self
    }
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn get_workload_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workload_id
    }
    /// <p>The ARN for the workload.</p>
    pub fn workload_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workload_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the workload.</p>
    pub fn set_workload_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workload_arn = input;
        self
    }
    /// <p>The ARN for the workload.</p>
    pub fn get_workload_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.workload_arn
    }
    /// <p>The name of the workload.</p>
    /// <p>The name must be unique within an account within an Amazon Web Services Region. Spaces and capitalization are ignored when checking for uniqueness.</p>
    pub fn workload_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workload_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the workload.</p>
    /// <p>The name must be unique within an account within an Amazon Web Services Region. Spaces and capitalization are ignored when checking for uniqueness.</p>
    pub fn set_workload_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workload_name = input;
        self
    }
    /// <p>The name of the workload.</p>
    /// <p>The name must be unique within an account within an Amazon Web Services Region. Spaces and capitalization are ignored when checking for uniqueness.</p>
    pub fn get_workload_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.workload_name
    }
    /// <p>An Amazon Web Services account ID.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Amazon Web Services account ID.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>An Amazon Web Services account ID.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// <p>The date and time recorded.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time recorded.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time recorded.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// Appends an item to `lenses`.
    ///
    /// To override the contents of this collection use [`set_lenses`](Self::set_lenses).
    ///
    /// <p>The list of lenses associated with the workload. Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    /// <p>If a review template that specifies lenses is applied to the workload, those lenses are applied to the workload in addition to these lenses.</p>
    pub fn lenses(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.lenses.unwrap_or_default();
        v.push(input.into());
        self.lenses = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of lenses associated with the workload. Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    /// <p>If a review template that specifies lenses is applied to the workload, those lenses are applied to the workload in addition to these lenses.</p>
    pub fn set_lenses(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.lenses = input;
        self
    }
    /// <p>The list of lenses associated with the workload. Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    /// <p>If a review template that specifies lenses is applied to the workload, those lenses are applied to the workload in addition to these lenses.</p>
    pub fn get_lenses(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.lenses
    }
    /// Adds a key-value pair to `risk_counts`.
    ///
    /// To override the contents of this collection use [`set_risk_counts`](Self::set_risk_counts).
    ///
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub fn risk_counts(mut self, k: crate::types::Risk, v: i32) -> Self {
        let mut hash_map = self.risk_counts.unwrap_or_default();
        hash_map.insert(k, v);
        self.risk_counts = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub fn set_risk_counts(mut self, input: ::std::option::Option<::std::collections::HashMap<crate::types::Risk, i32>>) -> Self {
        self.risk_counts = input;
        self
    }
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub fn get_risk_counts(&self) -> &::std::option::Option<::std::collections::HashMap<crate::types::Risk, i32>> {
        &self.risk_counts
    }
    /// <p>The improvement status for a workload.</p>
    pub fn improvement_status(mut self, input: crate::types::WorkloadImprovementStatus) -> Self {
        self.improvement_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The improvement status for a workload.</p>
    pub fn set_improvement_status(mut self, input: ::std::option::Option<crate::types::WorkloadImprovementStatus>) -> Self {
        self.improvement_status = input;
        self
    }
    /// <p>The improvement status for a workload.</p>
    pub fn get_improvement_status(&self) -> &::std::option::Option<crate::types::WorkloadImprovementStatus> {
        &self.improvement_status
    }
    /// Appends an item to `profiles`.
    ///
    /// To override the contents of this collection use [`set_profiles`](Self::set_profiles).
    ///
    /// <p>Profile associated with a workload.</p>
    pub fn profiles(mut self, input: crate::types::WorkloadProfile) -> Self {
        let mut v = self.profiles.unwrap_or_default();
        v.push(input);
        self.profiles = ::std::option::Option::Some(v);
        self
    }
    /// <p>Profile associated with a workload.</p>
    pub fn set_profiles(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WorkloadProfile>>) -> Self {
        self.profiles = input;
        self
    }
    /// <p>Profile associated with a workload.</p>
    pub fn get_profiles(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WorkloadProfile>> {
        &self.profiles
    }
    /// Adds a key-value pair to `prioritized_risk_counts`.
    ///
    /// To override the contents of this collection use [`set_prioritized_risk_counts`](Self::set_prioritized_risk_counts).
    ///
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub fn prioritized_risk_counts(mut self, k: crate::types::Risk, v: i32) -> Self {
        let mut hash_map = self.prioritized_risk_counts.unwrap_or_default();
        hash_map.insert(k, v);
        self.prioritized_risk_counts = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub fn set_prioritized_risk_counts(mut self, input: ::std::option::Option<::std::collections::HashMap<crate::types::Risk, i32>>) -> Self {
        self.prioritized_risk_counts = input;
        self
    }
    /// <p>A map from risk names to the count of how many questions have that rating.</p>
    pub fn get_prioritized_risk_counts(&self) -> &::std::option::Option<::std::collections::HashMap<crate::types::Risk, i32>> {
        &self.prioritized_risk_counts
    }
    /// Consumes the builder and constructs a [`WorkloadSummary`](crate::types::WorkloadSummary).
    pub fn build(self) -> crate::types::WorkloadSummary {
        crate::types::WorkloadSummary {
            workload_id: self.workload_id,
            workload_arn: self.workload_arn,
            workload_name: self.workload_name,
            owner: self.owner,
            updated_at: self.updated_at,
            lenses: self.lenses,
            risk_counts: self.risk_counts,
            improvement_status: self.improvement_status,
            profiles: self.profiles,
            prioritized_risk_counts: self.prioritized_risk_counts,
        }
    }
}
