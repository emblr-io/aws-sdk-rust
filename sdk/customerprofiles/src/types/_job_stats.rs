// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Statistics about the Identity Resolution Job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JobStats {
    /// <p>The number of profiles reviewed.</p>
    pub number_of_profiles_reviewed: i64,
    /// <p>The number of matches found.</p>
    pub number_of_matches_found: i64,
    /// <p>The number of merges completed.</p>
    pub number_of_merges_done: i64,
}
impl JobStats {
    /// <p>The number of profiles reviewed.</p>
    pub fn number_of_profiles_reviewed(&self) -> i64 {
        self.number_of_profiles_reviewed
    }
    /// <p>The number of matches found.</p>
    pub fn number_of_matches_found(&self) -> i64 {
        self.number_of_matches_found
    }
    /// <p>The number of merges completed.</p>
    pub fn number_of_merges_done(&self) -> i64 {
        self.number_of_merges_done
    }
}
impl JobStats {
    /// Creates a new builder-style object to manufacture [`JobStats`](crate::types::JobStats).
    pub fn builder() -> crate::types::builders::JobStatsBuilder {
        crate::types::builders::JobStatsBuilder::default()
    }
}

/// A builder for [`JobStats`](crate::types::JobStats).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobStatsBuilder {
    pub(crate) number_of_profiles_reviewed: ::std::option::Option<i64>,
    pub(crate) number_of_matches_found: ::std::option::Option<i64>,
    pub(crate) number_of_merges_done: ::std::option::Option<i64>,
}
impl JobStatsBuilder {
    /// <p>The number of profiles reviewed.</p>
    pub fn number_of_profiles_reviewed(mut self, input: i64) -> Self {
        self.number_of_profiles_reviewed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of profiles reviewed.</p>
    pub fn set_number_of_profiles_reviewed(mut self, input: ::std::option::Option<i64>) -> Self {
        self.number_of_profiles_reviewed = input;
        self
    }
    /// <p>The number of profiles reviewed.</p>
    pub fn get_number_of_profiles_reviewed(&self) -> &::std::option::Option<i64> {
        &self.number_of_profiles_reviewed
    }
    /// <p>The number of matches found.</p>
    pub fn number_of_matches_found(mut self, input: i64) -> Self {
        self.number_of_matches_found = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of matches found.</p>
    pub fn set_number_of_matches_found(mut self, input: ::std::option::Option<i64>) -> Self {
        self.number_of_matches_found = input;
        self
    }
    /// <p>The number of matches found.</p>
    pub fn get_number_of_matches_found(&self) -> &::std::option::Option<i64> {
        &self.number_of_matches_found
    }
    /// <p>The number of merges completed.</p>
    pub fn number_of_merges_done(mut self, input: i64) -> Self {
        self.number_of_merges_done = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of merges completed.</p>
    pub fn set_number_of_merges_done(mut self, input: ::std::option::Option<i64>) -> Self {
        self.number_of_merges_done = input;
        self
    }
    /// <p>The number of merges completed.</p>
    pub fn get_number_of_merges_done(&self) -> &::std::option::Option<i64> {
        &self.number_of_merges_done
    }
    /// Consumes the builder and constructs a [`JobStats`](crate::types::JobStats).
    pub fn build(self) -> crate::types::JobStats {
        crate::types::JobStats {
            number_of_profiles_reviewed: self.number_of_profiles_reviewed.unwrap_or_default(),
            number_of_matches_found: self.number_of_matches_found.unwrap_or_default(),
            number_of_merges_done: self.number_of_merges_done.unwrap_or_default(),
        }
    }
}
