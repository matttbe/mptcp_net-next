#! /bin/bash
#
# The goal is to regularly sync 'net-next' branch on this repo with Davem's one.
# Then our topgit tree can be updated and the modifications can be pushed only
# after a successful build and tests. In case of problem, a notification will be
# sent to Matthieu Baerts.

# We should manage all errors in this script
set -e

# Github remote
GIT_REMOTE_GITHUB_NAME="origin"

# Davem remote
GIT_REMOTE_NET_NEXT_URL="git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git"
GIT_REMOTE_NET_NEXT_BRANCH="master"

# Local repo
TG_TOPIC_BASE="net-next"
TG_TOPIC_TOP="t/upstream"
TG_EXPORT_BRANCH="export"
TG_FOR_REVIEW_BRANCH="for-review"


###########
## Utils ##
###########

# $@: message to display before quiting
exit_err() {
	echo "ERROR: ${*}"
	exit 1
}

# $1: branch ;  [ $2: remote, default: origin ]
git_checkout() { local branch remote
	branch="${1}"
	remote="${2:-${GIT_REMOTE_GITHUB_NAME}}"

	git checkout -f "${branch}" || git checkout -b "${branch}" "${remote}/${branch}"
}

git_clean() {
	# no need to remove .gitignored files, should be handle by git and we might
	# need these files (.config, scripts, etc.)
	git clean -fd
}

# [ $1: ref, default: HEAD ]
git_get_sha() {
	git rev-parse "${1:-HEAD}"
}


###############
## TG Update ##
###############

tg_update_base() { local sha_before_update
	git_checkout "${TG_TOPIC_BASE}"

	if [ "${UPD_TG_NOT_BASE}" = 1 ]; then
		git pull --ff-only "${GIT_REMOTE_GITHUB_NAME}" \
			"${TG_TOPIC_BASE}"
		return 0
	fi

	sha_before_update=$(git_get_sha HEAD)

	# this branch has to be in sync with upstream, no merge
	git pull --ff-only "${GIT_REMOTE_NET_NEXT_URL}" "${GIT_REMOTE_NET_NEXT_BRANCH}"
	if [ "${UPD_TG_FORCE_SYNC}" != 1 ] && \
	   [ "${sha_before_update}" = "$(git_get_sha HEAD)" ]; then
		echo "Already sync with ${GIT_REMOTE_NET_NEXT_URL} (${sha_before_update})"
		exit 0
	fi

	git push "${GIT_REMOTE_GITHUB_NAME}" "${TG_TOPIC_BASE}"
}

tg_update() { local rc=0
	tg update || rc="${?}"

	if [ "${rc}" != 0 ]; then
		tg update --abort
	fi

	return "${rc}"
}

tg_update_tree() {
	git_checkout "${TG_TOPIC_TOP}"

	git fetch "${GIT_REMOTE_GITHUB_NAME}"

	# force to add TG refs in refs/top-bases/, errit is configured for a
	# use with these refs and here below, we also use them.
	git config --local topgit.top-bases refs

	# fetch and update-ref will be done
	tg remote "${GIT_REMOTE_GITHUB_NAME}" --populate

	# do that twice (if there is no error) just in case the base and the
	# rest of the tree were not sync. It can happen if the tree has been
	# updated by someone else and after, the base (only) has been updated.
	# At the beginning of this script, we force an update of the base.
	tg_update
	tg_update
}

tg_get_all_topics() {
	git for-each-ref --format="%(refname)" "refs/remotes/${GIT_REMOTE_GITHUB_NAME}/top-bases/" | \
		sed -e "s#refs/remotes/${GIT_REMOTE_GITHUB_NAME}/top-bases/\\(.*\\)#\\1#g"
}

tg_reset() { local topic
	for topic in $(tg_get_all_topics); do
		git update-ref "refs/top-bases/${topic}" \
			"refs/remotes/${GIT_REMOTE_GITHUB_NAME}/top-bases/${topic}"
		git update-ref "refs/heads/${topic}" "refs/remotes/${GIT_REMOTE_GITHUB_NAME}/${topic}"
	done
	# the base should be already up to date anyway.
	git update-ref "refs/heads/${TG_TOPIC_BASE}" "refs/remotes/${GIT_REMOTE_GITHUB_NAME}/${TG_TOPIC_BASE}"
}

# $1: last return code
tg_trap_reset() { local rc
	rc="${1}"

	# check return code: if different than 0, we exit with an error: reset
	[ "${rc}" -eq 0 ] && return 0

	tg_reset

	exit "${rc}"
}


################
## Validation ##
################

generate_config_no_mptcp() {
	make defconfig

	# no need to compile this GPU driver for our tests
	echo | scripts/config --disable DRM_I915
}

generate_config_mptcp() {
	generate_config_no_mptcp

	echo | scripts/config --enable MPTCP

	# Here, we want to have a failure if some new MPTCP options are
	# available not to forget to enable them. We then don't want to run
	# 'make olddefconfig' which will silently disable these new options.
}

compile_kernel() {
	make -j"$(nproc)" -l"$(nproc)"
}

check_compilation() {
	generate_config_no_mptcp
	compile_kernel || exit_err "Unable to compile the new version without CONFIG_MPTCP"

	generate_config_mptcp
	compile_kernel || exit_err "Unable to compile the new version with CONFIG_MPTCP"
}

validation() {
	check_compilation || exit_err "Unable to compile the new version"
}


############
## TG End ##
############

tg_push_tree() {
	git_checkout "${TG_TOPIC_TOP}"

	tg push -r "${GIT_REMOTE_GITHUB_NAME}"
}

tg_export() { local current_date tag
	git_checkout "${TG_TOPIC_TOP}"

	current_date=$(date +%Y%m%dT%H%M%S)
	tag="${TG_EXPORT_BRANCH}/${current_date}"

	tg export --linearize --force "${TG_EXPORT_BRANCH}"
	git push --force "${GIT_REMOTE_GITHUB_NAME}" "${TG_EXPORT_BRANCH}"

	# send a tag to Github to keep previous commits: we might have refs to them
	git tag "${tag}" "${TG_EXPORT_BRANCH}"
	git push "${GIT_REMOTE_GITHUB_URL}" "${tag}"
}

tg_for_review() { local tg_conflict_files
	git_checkout "${TG_FOR_REVIEW_BRANCH}"

	git pull "${GIT_REMOTE_GITHUB_NAME}" "${TG_FOR_REVIEW_BRANCH}"

	if ! git merge --no-edit --signoff "${TG_TOPIC_TOP}"; then
		# the only possible conflict would be with the topgit files, manage this
		tg_conflict_files=$(git status --porcelain | grep -E "^DU\\s.top(deps|msg)$")
		if [ -n "${tg_conflict_files}" ]; then
			echo "${tg_conflict_files}" | awk '{ print $2 }' | xargs git rm
			git commit -s --no-edit || \
				exit_err "Unexpected other conflicts: ${tg_conflict_files}"
		else
			exit_err "Unexpected conflicts when updating ${TG_FOR_REVIEW_BRANCH}"
		fi
	fi

	git push "${GIT_REMOTE_GITHUB_NAME}" "${TG_FOR_REVIEW_BRANCH}"
}


##########
## Main ##
##########

git_clean || exit_err "Unable to clean the environment"
tg_update_base || exit_err "Unable to update the topgit base"
trap 'tg_trap_reset "${?}"' EXIT
tg_update_tree || exit_err "Unable to update the topgit tree"
validation || exit_err "Unexpected error during the validation phase"
tg_push_tree || exit_err "Unable to push the update of the Topgit tree"
tg_export || exit_err "Unable to export the TopGit tree"
tg_for_review || exit_err "Unable to update the ${TG_FOR_REVIEW_BRANCH} branch"
