# all-review
In-house peer review system.

## Usage

    ./main.py -h  # Show command-line options
    ./main.py     # Start with default options

## Dependencies

Install these with `pip install`:

 * tornado
 * markdown


## TODO list

 * add an edit/reupload/delete option for reviews/uploads
  - should only appear if username == author
 * add an admin page for adding/deleting users
  - admin user should also be able to modify other users' uploads/reviews
