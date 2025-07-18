// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains a list of the first 100 <code>RUNNABLE</code> jobs associated to a single job queue.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FrontOfQueueDetail {
    /// <p>The Amazon Resource Names (ARNs) of the first 100 <code>RUNNABLE</code> jobs in a named job queue. For first-in-first-out (FIFO) job queues, jobs are ordered based on their submission time. For fair-share scheduling (FSS) job queues, jobs are ordered based on their job priority and share usage.</p>
    pub jobs: ::std::option::Option<::std::vec::Vec<crate::types::FrontOfQueueJobSummary>>,
    /// <p>The Unix timestamp (in milliseconds) for when each of the first 100 <code>RUNNABLE</code> jobs were last updated.</p>
    pub last_updated_at: ::std::option::Option<i64>,
}
impl FrontOfQueueDetail {
    /// <p>The Amazon Resource Names (ARNs) of the first 100 <code>RUNNABLE</code> jobs in a named job queue. For first-in-first-out (FIFO) job queues, jobs are ordered based on their submission time. For fair-share scheduling (FSS) job queues, jobs are ordered based on their job priority and share usage.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.jobs.is_none()`.
    pub fn jobs(&self) -> &[crate::types::FrontOfQueueJobSummary] {
        self.jobs.as_deref().unwrap_or_default()
    }
    /// <p>The Unix timestamp (in milliseconds) for when each of the first 100 <code>RUNNABLE</code> jobs were last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<i64> {
        self.last_updated_at
    }
}
impl FrontOfQueueDetail {
    /// Creates a new builder-style object to manufacture [`FrontOfQueueDetail`](crate::types::FrontOfQueueDetail).
    pub fn builder() -> crate::types::builders::FrontOfQueueDetailBuilder {
        crate::types::builders::FrontOfQueueDetailBuilder::default()
    }
}

/// A builder for [`FrontOfQueueDetail`](crate::types::FrontOfQueueDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FrontOfQueueDetailBuilder {
    pub(crate) jobs: ::std::option::Option<::std::vec::Vec<crate::types::FrontOfQueueJobSummary>>,
    pub(crate) last_updated_at: ::std::option::Option<i64>,
}
impl FrontOfQueueDetailBuilder {
    /// Appends an item to `jobs`.
    ///
    /// To override the contents of this collection use [`set_jobs`](Self::set_jobs).
    ///
    /// <p>The Amazon Resource Names (ARNs) of the first 100 <code>RUNNABLE</code> jobs in a named job queue. For first-in-first-out (FIFO) job queues, jobs are ordered based on their submission time. For fair-share scheduling (FSS) job queues, jobs are ordered based on their job priority and share usage.</p>
    pub fn jobs(mut self, input: crate::types::FrontOfQueueJobSummary) -> Self {
        let mut v = self.jobs.unwrap_or_default();
        v.push(input);
        self.jobs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Names (ARNs) of the first 100 <code>RUNNABLE</code> jobs in a named job queue. For first-in-first-out (FIFO) job queues, jobs are ordered based on their submission time. For fair-share scheduling (FSS) job queues, jobs are ordered based on their job priority and share usage.</p>
    pub fn set_jobs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FrontOfQueueJobSummary>>) -> Self {
        self.jobs = input;
        self
    }
    /// <p>The Amazon Resource Names (ARNs) of the first 100 <code>RUNNABLE</code> jobs in a named job queue. For first-in-first-out (FIFO) job queues, jobs are ordered based on their submission time. For fair-share scheduling (FSS) job queues, jobs are ordered based on their job priority and share usage.</p>
    pub fn get_jobs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FrontOfQueueJobSummary>> {
        &self.jobs
    }
    /// <p>The Unix timestamp (in milliseconds) for when each of the first 100 <code>RUNNABLE</code> jobs were last updated.</p>
    pub fn last_updated_at(mut self, input: i64) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp (in milliseconds) for when each of the first 100 <code>RUNNABLE</code> jobs were last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<i64>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The Unix timestamp (in milliseconds) for when each of the first 100 <code>RUNNABLE</code> jobs were last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<i64> {
        &self.last_updated_at
    }
    /// Consumes the builder and constructs a [`FrontOfQueueDetail`](crate::types::FrontOfQueueDetail).
    pub fn build(self) -> crate::types::FrontOfQueueDetail {
        crate::types::FrontOfQueueDetail {
            jobs: self.jobs,
            last_updated_at: self.last_updated_at,
        }
    }
}
