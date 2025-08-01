// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An answer of the question.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReviewTemplateAnswer {
    /// <p>The ID of the question.</p>
    pub question_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID used to identify a pillar, for example, <code>security</code>.</p>
    /// <p>A pillar is identified by its <code>PillarReviewSummary$PillarId</code>.</p>
    pub pillar_id: ::std::option::Option<::std::string::String>,
    /// <p>The title of the question.</p>
    pub question_title: ::std::option::Option<::std::string::String>,
    /// <p>The description of the question.</p>
    pub question_description: ::std::option::Option<::std::string::String>,
    /// <p>The improvement plan URL for a question in an Amazon Web Services official lenses.</p>
    /// <p>This value is only available if the question has been answered.</p>
    /// <p>This value does not apply to custom lenses.</p>
    pub improvement_plan_url: ::std::option::Option<::std::string::String>,
    /// <p>The helpful resource URL.</p>
    /// <p>For Amazon Web Services official lenses, this is the helpful resource URL for a question or choice.</p>
    /// <p>For custom lenses, this is the helpful resource URL for a question and is only provided if <code>HelpfulResourceDisplayText</code> was specified for the question.</p>
    pub helpful_resource_url: ::std::option::Option<::std::string::String>,
    /// <p>The helpful resource text to be displayed for a custom lens.</p><note>
    /// <p>This field does not apply to Amazon Web Services official lenses.</p>
    /// </note>
    pub helpful_resource_display_text: ::std::option::Option<::std::string::String>,
    /// <p>List of choices available for a question.</p>
    pub choices: ::std::option::Option<::std::vec::Vec<crate::types::Choice>>,
    /// <p>List of selected choice IDs in a question answer.</p>
    /// <p>The values entered replace the previously selected choices.</p>
    pub selected_choices: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of selected choices to a question in your review template.</p>
    pub choice_answers: ::std::option::Option<::std::vec::Vec<crate::types::ChoiceAnswer>>,
    /// <p>Defines whether this question is applicable to a lens review.</p>
    pub is_applicable: ::std::option::Option<bool>,
    /// <p>The status of whether or not this question has been answered.</p>
    pub answer_status: ::std::option::Option<crate::types::ReviewTemplateAnswerStatus>,
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub notes: ::std::option::Option<::std::string::String>,
    /// <p>The reason why the question is not applicable to your review template.</p>
    pub reason: ::std::option::Option<crate::types::AnswerReason>,
}
impl ReviewTemplateAnswer {
    /// <p>The ID of the question.</p>
    pub fn question_id(&self) -> ::std::option::Option<&str> {
        self.question_id.as_deref()
    }
    /// <p>The ID used to identify a pillar, for example, <code>security</code>.</p>
    /// <p>A pillar is identified by its <code>PillarReviewSummary$PillarId</code>.</p>
    pub fn pillar_id(&self) -> ::std::option::Option<&str> {
        self.pillar_id.as_deref()
    }
    /// <p>The title of the question.</p>
    pub fn question_title(&self) -> ::std::option::Option<&str> {
        self.question_title.as_deref()
    }
    /// <p>The description of the question.</p>
    pub fn question_description(&self) -> ::std::option::Option<&str> {
        self.question_description.as_deref()
    }
    /// <p>The improvement plan URL for a question in an Amazon Web Services official lenses.</p>
    /// <p>This value is only available if the question has been answered.</p>
    /// <p>This value does not apply to custom lenses.</p>
    pub fn improvement_plan_url(&self) -> ::std::option::Option<&str> {
        self.improvement_plan_url.as_deref()
    }
    /// <p>The helpful resource URL.</p>
    /// <p>For Amazon Web Services official lenses, this is the helpful resource URL for a question or choice.</p>
    /// <p>For custom lenses, this is the helpful resource URL for a question and is only provided if <code>HelpfulResourceDisplayText</code> was specified for the question.</p>
    pub fn helpful_resource_url(&self) -> ::std::option::Option<&str> {
        self.helpful_resource_url.as_deref()
    }
    /// <p>The helpful resource text to be displayed for a custom lens.</p><note>
    /// <p>This field does not apply to Amazon Web Services official lenses.</p>
    /// </note>
    pub fn helpful_resource_display_text(&self) -> ::std::option::Option<&str> {
        self.helpful_resource_display_text.as_deref()
    }
    /// <p>List of choices available for a question.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.choices.is_none()`.
    pub fn choices(&self) -> &[crate::types::Choice] {
        self.choices.as_deref().unwrap_or_default()
    }
    /// <p>List of selected choice IDs in a question answer.</p>
    /// <p>The values entered replace the previously selected choices.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.selected_choices.is_none()`.
    pub fn selected_choices(&self) -> &[::std::string::String] {
        self.selected_choices.as_deref().unwrap_or_default()
    }
    /// <p>A list of selected choices to a question in your review template.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.choice_answers.is_none()`.
    pub fn choice_answers(&self) -> &[crate::types::ChoiceAnswer] {
        self.choice_answers.as_deref().unwrap_or_default()
    }
    /// <p>Defines whether this question is applicable to a lens review.</p>
    pub fn is_applicable(&self) -> ::std::option::Option<bool> {
        self.is_applicable
    }
    /// <p>The status of whether or not this question has been answered.</p>
    pub fn answer_status(&self) -> ::std::option::Option<&crate::types::ReviewTemplateAnswerStatus> {
        self.answer_status.as_ref()
    }
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub fn notes(&self) -> ::std::option::Option<&str> {
        self.notes.as_deref()
    }
    /// <p>The reason why the question is not applicable to your review template.</p>
    pub fn reason(&self) -> ::std::option::Option<&crate::types::AnswerReason> {
        self.reason.as_ref()
    }
}
impl ReviewTemplateAnswer {
    /// Creates a new builder-style object to manufacture [`ReviewTemplateAnswer`](crate::types::ReviewTemplateAnswer).
    pub fn builder() -> crate::types::builders::ReviewTemplateAnswerBuilder {
        crate::types::builders::ReviewTemplateAnswerBuilder::default()
    }
}

/// A builder for [`ReviewTemplateAnswer`](crate::types::ReviewTemplateAnswer).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReviewTemplateAnswerBuilder {
    pub(crate) question_id: ::std::option::Option<::std::string::String>,
    pub(crate) pillar_id: ::std::option::Option<::std::string::String>,
    pub(crate) question_title: ::std::option::Option<::std::string::String>,
    pub(crate) question_description: ::std::option::Option<::std::string::String>,
    pub(crate) improvement_plan_url: ::std::option::Option<::std::string::String>,
    pub(crate) helpful_resource_url: ::std::option::Option<::std::string::String>,
    pub(crate) helpful_resource_display_text: ::std::option::Option<::std::string::String>,
    pub(crate) choices: ::std::option::Option<::std::vec::Vec<crate::types::Choice>>,
    pub(crate) selected_choices: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) choice_answers: ::std::option::Option<::std::vec::Vec<crate::types::ChoiceAnswer>>,
    pub(crate) is_applicable: ::std::option::Option<bool>,
    pub(crate) answer_status: ::std::option::Option<crate::types::ReviewTemplateAnswerStatus>,
    pub(crate) notes: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<crate::types::AnswerReason>,
}
impl ReviewTemplateAnswerBuilder {
    /// <p>The ID of the question.</p>
    pub fn question_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.question_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the question.</p>
    pub fn set_question_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.question_id = input;
        self
    }
    /// <p>The ID of the question.</p>
    pub fn get_question_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.question_id
    }
    /// <p>The ID used to identify a pillar, for example, <code>security</code>.</p>
    /// <p>A pillar is identified by its <code>PillarReviewSummary$PillarId</code>.</p>
    pub fn pillar_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pillar_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID used to identify a pillar, for example, <code>security</code>.</p>
    /// <p>A pillar is identified by its <code>PillarReviewSummary$PillarId</code>.</p>
    pub fn set_pillar_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pillar_id = input;
        self
    }
    /// <p>The ID used to identify a pillar, for example, <code>security</code>.</p>
    /// <p>A pillar is identified by its <code>PillarReviewSummary$PillarId</code>.</p>
    pub fn get_pillar_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pillar_id
    }
    /// <p>The title of the question.</p>
    pub fn question_title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.question_title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The title of the question.</p>
    pub fn set_question_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.question_title = input;
        self
    }
    /// <p>The title of the question.</p>
    pub fn get_question_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.question_title
    }
    /// <p>The description of the question.</p>
    pub fn question_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.question_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the question.</p>
    pub fn set_question_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.question_description = input;
        self
    }
    /// <p>The description of the question.</p>
    pub fn get_question_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.question_description
    }
    /// <p>The improvement plan URL for a question in an Amazon Web Services official lenses.</p>
    /// <p>This value is only available if the question has been answered.</p>
    /// <p>This value does not apply to custom lenses.</p>
    pub fn improvement_plan_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.improvement_plan_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The improvement plan URL for a question in an Amazon Web Services official lenses.</p>
    /// <p>This value is only available if the question has been answered.</p>
    /// <p>This value does not apply to custom lenses.</p>
    pub fn set_improvement_plan_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.improvement_plan_url = input;
        self
    }
    /// <p>The improvement plan URL for a question in an Amazon Web Services official lenses.</p>
    /// <p>This value is only available if the question has been answered.</p>
    /// <p>This value does not apply to custom lenses.</p>
    pub fn get_improvement_plan_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.improvement_plan_url
    }
    /// <p>The helpful resource URL.</p>
    /// <p>For Amazon Web Services official lenses, this is the helpful resource URL for a question or choice.</p>
    /// <p>For custom lenses, this is the helpful resource URL for a question and is only provided if <code>HelpfulResourceDisplayText</code> was specified for the question.</p>
    pub fn helpful_resource_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.helpful_resource_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The helpful resource URL.</p>
    /// <p>For Amazon Web Services official lenses, this is the helpful resource URL for a question or choice.</p>
    /// <p>For custom lenses, this is the helpful resource URL for a question and is only provided if <code>HelpfulResourceDisplayText</code> was specified for the question.</p>
    pub fn set_helpful_resource_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.helpful_resource_url = input;
        self
    }
    /// <p>The helpful resource URL.</p>
    /// <p>For Amazon Web Services official lenses, this is the helpful resource URL for a question or choice.</p>
    /// <p>For custom lenses, this is the helpful resource URL for a question and is only provided if <code>HelpfulResourceDisplayText</code> was specified for the question.</p>
    pub fn get_helpful_resource_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.helpful_resource_url
    }
    /// <p>The helpful resource text to be displayed for a custom lens.</p><note>
    /// <p>This field does not apply to Amazon Web Services official lenses.</p>
    /// </note>
    pub fn helpful_resource_display_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.helpful_resource_display_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The helpful resource text to be displayed for a custom lens.</p><note>
    /// <p>This field does not apply to Amazon Web Services official lenses.</p>
    /// </note>
    pub fn set_helpful_resource_display_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.helpful_resource_display_text = input;
        self
    }
    /// <p>The helpful resource text to be displayed for a custom lens.</p><note>
    /// <p>This field does not apply to Amazon Web Services official lenses.</p>
    /// </note>
    pub fn get_helpful_resource_display_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.helpful_resource_display_text
    }
    /// Appends an item to `choices`.
    ///
    /// To override the contents of this collection use [`set_choices`](Self::set_choices).
    ///
    /// <p>List of choices available for a question.</p>
    pub fn choices(mut self, input: crate::types::Choice) -> Self {
        let mut v = self.choices.unwrap_or_default();
        v.push(input);
        self.choices = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of choices available for a question.</p>
    pub fn set_choices(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Choice>>) -> Self {
        self.choices = input;
        self
    }
    /// <p>List of choices available for a question.</p>
    pub fn get_choices(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Choice>> {
        &self.choices
    }
    /// Appends an item to `selected_choices`.
    ///
    /// To override the contents of this collection use [`set_selected_choices`](Self::set_selected_choices).
    ///
    /// <p>List of selected choice IDs in a question answer.</p>
    /// <p>The values entered replace the previously selected choices.</p>
    pub fn selected_choices(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.selected_choices.unwrap_or_default();
        v.push(input.into());
        self.selected_choices = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of selected choice IDs in a question answer.</p>
    /// <p>The values entered replace the previously selected choices.</p>
    pub fn set_selected_choices(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.selected_choices = input;
        self
    }
    /// <p>List of selected choice IDs in a question answer.</p>
    /// <p>The values entered replace the previously selected choices.</p>
    pub fn get_selected_choices(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.selected_choices
    }
    /// Appends an item to `choice_answers`.
    ///
    /// To override the contents of this collection use [`set_choice_answers`](Self::set_choice_answers).
    ///
    /// <p>A list of selected choices to a question in your review template.</p>
    pub fn choice_answers(mut self, input: crate::types::ChoiceAnswer) -> Self {
        let mut v = self.choice_answers.unwrap_or_default();
        v.push(input);
        self.choice_answers = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of selected choices to a question in your review template.</p>
    pub fn set_choice_answers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ChoiceAnswer>>) -> Self {
        self.choice_answers = input;
        self
    }
    /// <p>A list of selected choices to a question in your review template.</p>
    pub fn get_choice_answers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ChoiceAnswer>> {
        &self.choice_answers
    }
    /// <p>Defines whether this question is applicable to a lens review.</p>
    pub fn is_applicable(mut self, input: bool) -> Self {
        self.is_applicable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines whether this question is applicable to a lens review.</p>
    pub fn set_is_applicable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_applicable = input;
        self
    }
    /// <p>Defines whether this question is applicable to a lens review.</p>
    pub fn get_is_applicable(&self) -> &::std::option::Option<bool> {
        &self.is_applicable
    }
    /// <p>The status of whether or not this question has been answered.</p>
    pub fn answer_status(mut self, input: crate::types::ReviewTemplateAnswerStatus) -> Self {
        self.answer_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of whether or not this question has been answered.</p>
    pub fn set_answer_status(mut self, input: ::std::option::Option<crate::types::ReviewTemplateAnswerStatus>) -> Self {
        self.answer_status = input;
        self
    }
    /// <p>The status of whether or not this question has been answered.</p>
    pub fn get_answer_status(&self) -> &::std::option::Option<crate::types::ReviewTemplateAnswerStatus> {
        &self.answer_status
    }
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub fn notes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notes = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub fn set_notes(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notes = input;
        self
    }
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub fn get_notes(&self) -> &::std::option::Option<::std::string::String> {
        &self.notes
    }
    /// <p>The reason why the question is not applicable to your review template.</p>
    pub fn reason(mut self, input: crate::types::AnswerReason) -> Self {
        self.reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason why the question is not applicable to your review template.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<crate::types::AnswerReason>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The reason why the question is not applicable to your review template.</p>
    pub fn get_reason(&self) -> &::std::option::Option<crate::types::AnswerReason> {
        &self.reason
    }
    /// Consumes the builder and constructs a [`ReviewTemplateAnswer`](crate::types::ReviewTemplateAnswer).
    pub fn build(self) -> crate::types::ReviewTemplateAnswer {
        crate::types::ReviewTemplateAnswer {
            question_id: self.question_id,
            pillar_id: self.pillar_id,
            question_title: self.question_title,
            question_description: self.question_description,
            improvement_plan_url: self.improvement_plan_url,
            helpful_resource_url: self.helpful_resource_url,
            helpful_resource_display_text: self.helpful_resource_display_text,
            choices: self.choices,
            selected_choices: self.selected_choices,
            choice_answers: self.choice_answers,
            is_applicable: self.is_applicable,
            answer_status: self.answer_status,
            notes: self.notes,
            reason: self.reason,
        }
    }
}
