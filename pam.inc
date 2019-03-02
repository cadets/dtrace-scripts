
enum {
	PAM_SERVICE			=   1,
	PAM_USER			=   2,
	PAM_TTY				=   3,
	PAM_RHOST			=   4,
	PAM_CONV			=   5,
	PAM_AUTHTOK			=   6,
	PAM_OLDAUTHTOK			=   7,
	PAM_RUSER			=   8,
	PAM_USER_PROMPT			=   9,
	PAM_REPOSITORY			=  10,
	PAM_AUTHTOK_PROMPT		=  11,		/* OpenPAM extension */
	PAM_OLDAUTHTOK_PROMPT		=  12,		/* OpenPAM extension */
	PAM_HOST			=  13,		/* OpenPAM extension */
	PAM_NUM_ITEMS					/* OpenPAM extension */
};

/*
 * Control flags
 */
typedef enum {
	PAM_BINDING,
	PAM_REQUIRED,
	PAM_REQUISITE,
	PAM_SUFFICIENT,
	PAM_OPTIONAL,
	PAM_NUM_CONTROL_FLAGS
} pam_control_t;

/*
 * Facilities
 */
typedef enum {
	PAM_FACILITY_ANY = -1,
	PAM_AUTH = 0,
	PAM_ACCOUNT,
	PAM_SESSION,
	PAM_PASSWORD,
	PAM_NUM_FACILITIES
} pam_facility_t;

enum {
	PAM_SM_AUTHENTICATE,
	PAM_SM_SETCRED,
	PAM_SM_ACCT_MGMT,
	PAM_SM_OPEN_SESSION,
	PAM_SM_CLOSE_SESSION,
	PAM_SM_CHAUTHTOK,
	/* keep this last */
	PAM_NUM_PRIMITIVES
};
struct pam_handle;
typedef struct pam_handle pam_handle_t;

typedef int (*pam_func_t)(struct pam_handle *, int, int, const char **);

/*
 * A struct that describes a module.
 */
typedef struct pam_module pam_module_t;
struct pam_module {
	char		*path;
	pam_func_t	 func[PAM_NUM_PRIMITIVES];
	void		*dlh;
};

typedef struct pam_chain pam_chain_t;
struct pam_chain {
	pam_module_t	*module;
	int		 flag;
	int		 optc;
	char	       **optv;
	pam_chain_t	*next;
};

typedef struct pam_data pam_data_t;
struct pam_data {
	char		*name;
	void		*data;
	void		(*cleanup)(pam_handle_t *, void *, int);
	pam_data_t	*next;
};

struct pam_handle {
	char		*service;

	/* chains */
	pam_chain_t	*chains[PAM_NUM_FACILITIES];
	pam_chain_t	*current;
	int		 primitive;

	/* items and data */
	void		*item[PAM_NUM_ITEMS];
	pam_data_t	*module_data;

	/* environment list */
	char	       **env;
	int		 env_count;
	int		 env_size;
};


